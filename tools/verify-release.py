#!/usr/bin/env python3
"""Verify release inputs without promoting missing hardware evidence to a pass."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
FULL_REVISION = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PENDING_REVISION = "pending-commit"
PENDING_STATE = "pending_commit_bound_evidence"
PENDING_RELEASE_CLAIM = (
    "blocked_pending_commit_bound_software_hardware_and_signed_artifact_evidence"
)
SOFTWARE_EVIDENCE = (
    "host_replay",
    "thread_sanitizer",
    "static_analysis",
    "source_security_scan",
    "build_tool_dependency_scan",
    "installed_consumers",
    "api_abi_generation",
    "android_cross_compile",
    "android_emulator",
    "ios_source_compile",
    "ios_simulator",
    "pcsc_transport_compile",
)
HARDWARE_EVIDENCE = (
    "android_physical_nfc",
    "ios_physical_nfc",
    "physical_ev3_card",
    "pcsc_reader",
)
QUALIFICATION_ONLY_FILES = {
    "docs/testing.md",
    "spec/coverage.md",
    "spec/qualification-record.yaml",
}
QUALIFICATION_ONLY_PREFIXES = ("docs/qualification/",)


def run(command: list[str]) -> list[str]:
    """Run one deterministic repository check and return a concise failure description."""
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if completed.returncode == 0:
        return []
    detail = (completed.stderr or completed.stdout).strip()
    return [f"{' '.join(command)} failed: {detail}"]


def scalar(document: str, *path: str) -> str | None:
    """Read one scalar from the repository's deliberately simple qualification YAML."""
    stack: list[str] = []
    for raw_line in document.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indentation = len(raw_line) - len(raw_line.lstrip(" "))
        if indentation % 2 != 0:
            continue
        key, separator, value = raw_line.strip().partition(":")
        if not separator:
            continue
        depth = indentation // 2
        stack = stack[:depth]
        stack.append(key)
        if tuple(stack) == path:
            return value.strip() or None
    return None


def integer_scalar(document: str, failures: list[str], *path: str) -> int | None:
    """Read one required decimal qualification scalar and report malformed content."""
    value = scalar(document, *path)
    if value is None or not value.isdecimal():
        failures.append(f"qualification field {'.'.join(path)} must be a decimal integer")
        return None
    return int(value)


def qualification_only_path(path: str) -> bool:
    """Return whether a path may follow the recorded source revision as evidence only."""
    return path in QUALIFICATION_ONLY_FILES or path.startswith(QUALIFICATION_ONLY_PREFIXES)


def validate_software_revision(revision: str, failures: list[str]) -> None:
    """Bind software evidence to HEAD or an ancestor followed only by evidence changes."""
    commit = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if commit.returncode != 0:
        failures.append(f"qualification software_revision is not a Git commit: {revision}")
        return

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if head.returncode != 0:
        failures.append("cannot resolve repository HEAD for qualification validation")
        return
    if head.stdout.strip() == revision:
        return

    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if ancestry.returncode != 0:
        failures.append("qualification software_revision must be HEAD or an ancestor of HEAD")
        return

    changed = subprocess.run(
        [
            "git",
            "diff",
            "--no-renames",
            "--name-only",
            "--diff-filter=ACDMRTUXB",
            f"{revision}..HEAD",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if changed.returncode != 0:
        failures.append("cannot enumerate changes after qualification software_revision")
        return
    unexpected = sorted(
        path for path in changed.stdout.splitlines() if path and not qualification_only_path(path)
    )
    if unexpected:
        failures.append(
            "non-qualification changes follow qualification software_revision: "
            + ", ".join(unexpected)
        )


def repository_file(value: str | None) -> pathlib.Path | None:
    """Resolve a repository-relative evidence path without accepting traversal or absolutes."""
    if value is None:
        return None
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    candidate = ROOT.joinpath(*relative.parts)
    return candidate if candidate.is_file() else None


def validate_qualification(document: str, digest: str, failures: list[str]) -> None:
    """Require the qualification record to identify current or explicitly pending evidence."""
    schema_version = integer_scalar(document, failures, "schema_version")
    if schema_version is not None and schema_version != 2:
        failures.append("qualification schema_version must equal 2")

    recorded_digest = scalar(document, "canonical_manifest_sha256")
    if recorded_digest != digest:
        failures.append("qualification canonical_manifest_sha256 differs from api/ev3-api.sha256")

    manifest = json.loads((ROOT / "api" / "ev3-api.json").read_text(encoding="utf-8"))
    expected_operations = len(manifest.get("operations", []))
    recorded_operations = integer_scalar(document, failures, "api_operations")
    if recorded_operations is not None and recorded_operations != expected_operations:
        failures.append(
            f"qualification api_operations is {recorded_operations}, expected {expected_operations}"
        )

    symbols = (ROOT / "c-api" / "abi" / "abi-v1.symbols").read_text(encoding="utf-8")
    expected_exports = sum(
        bool(line.strip()) and not line.lstrip().startswith("#") for line in symbols.splitlines()
    )
    recorded_exports = integer_scalar(document, failures, "abi_exports")
    if recorded_exports is not None and recorded_exports != expected_exports:
        failures.append(
            f"qualification abi_exports is {recorded_exports}, expected {expected_exports}"
        )

    revision = scalar(document, "software_revision")
    state = scalar(document, "qualification_state")
    release_claim = scalar(document, "release_claim")
    if revision == PENDING_REVISION:
        if state != PENDING_STATE:
            failures.append(f"pending qualification_state must equal {PENDING_STATE}")
        if release_claim != PENDING_RELEASE_CLAIM:
            failures.append(f"pending release_claim must equal {PENDING_RELEASE_CLAIM}")
        for item in SOFTWARE_EVIDENCE:
            status = scalar(document, "evidence", item, "status")
            if status is not None and status.startswith("passed"):
                failures.append(
                    f"pending qualification cannot record current evidence as passed: {item}"
                )
    elif revision is None or not FULL_REVISION.fullmatch(revision):
        failures.append("qualification software_revision must be pending-commit or a full Git SHA")
    else:
        validate_software_revision(revision, failures)
        if state != "commit_bound_evidence":
            failures.append("commit-bound qualification_state must equal commit_bound_evidence")

    for item in SOFTWARE_EVIDENCE:
        if scalar(document, "evidence", item, "status") is None:
            failures.append(f"qualification evidence.{item}.status is missing")

    for item in HARDWARE_EVIDENCE:
        if scalar(document, "evidence", item, "status") is None:
            failures.append(f"qualification evidence.{item}.status is missing")

    historical_revision = scalar(document, "historical_evidence", "source_revision")
    historical_digest = scalar(document, "historical_evidence", "manifest_sha256")
    historical_summary = scalar(document, "historical_evidence", "summary")
    if historical_revision is None or not FULL_REVISION.fullmatch(historical_revision):
        failures.append("historical_evidence.source_revision must be a full Git SHA")
    elif run(["git", "cat-file", "-e", f"{historical_revision}^{{commit}}"]):
        failures.append("historical_evidence.source_revision is not a Git commit")
    if historical_digest is None or not SHA256.fullmatch(historical_digest):
        failures.append("historical_evidence.manifest_sha256 must be a SHA-256 digest")
    if repository_file(historical_summary) is None:
        failures.append(
            "historical_evidence.summary must name an existing repository-relative file"
        )


def main() -> int:
    """Check manifests, required packaging inputs, and optionally qualification evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-software",
        action="store_true",
        help="fail unless all commit-bound software qualification rows are recorded as passed",
    )
    parser.add_argument(
        "--require-hardware",
        action="store_true",
        help="also require physical EV3, reader, Android NFC, and iOS NFC rows to be passed",
    )
    arguments = parser.parse_args()
    failures: list[str] = []

    failures.extend(run([sys.executable, "tools/check-format.py"]))
    failures.extend(run([sys.executable, "tools/check-cpp-documentation.py"]))
    failures.extend(run([sys.executable, "tools/check-api-coverage.py", "--check"]))
    failures.extend(run([sys.executable, "tools/generate-bindings.py", "--check"]))
    failures.extend(run([sys.executable, "sdk/node/tools/generate.py", "--check"]))
    failures.extend(run([sys.executable, "sdk/python/tools/generate_operations.py", "--check"]))
    failures.extend(run([sys.executable, "sdk/kotlin/tools/generate_bindings.py", "--check"]))
    failures.extend(run([sys.executable, "tools/check-coverage.py"]))
    failures.extend(run([sys.executable, "tools/check-abi.py"]))
    failures.extend(run([sys.executable, "tools/security/check-supply-chain.py"]))

    required = (
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "CHANGELOG.md",
        "api/abi-v1.json",
        "api/ev3-api.sha256",
        "spec/qualification-record.yaml",
        "docs/qualification/hardware-acceptance.md",
    )
    failures.extend(f"missing release input: {path}" for path in required if not (ROOT / path).is_file())

    digest = (ROOT / "api" / "ev3-api.sha256").read_text().strip()
    if not SHA256.fullmatch(digest):
        failures.append("api/ev3-api.sha256 is not a SHA-256 digest")

    manifest_digest = hashlib.sha256((ROOT / "api" / "ev3-api.json").read_bytes()).hexdigest()
    if manifest_digest == digest:
        failures.append("API identity must hash canonical JSON, not incidental file formatting")

    qualification_path = ROOT / "spec" / "qualification-record.yaml"
    if qualification_path.is_file():
        qualification = qualification_path.read_text(encoding="utf-8")
        validate_qualification(qualification, digest, failures)
    else:
        qualification = ""

    if arguments.require_software or arguments.require_hardware:
        if scalar(qualification, "software_revision") == PENDING_REVISION:
            failures.append("required software evidence cannot be bound to pending-commit")
        for item in SOFTWARE_EVIDENCE:
            status = scalar(qualification, "evidence", item, "status") or ""
            if not status.startswith("passed"):
                failures.append(f"required software evidence is not passed: {item}")

    if arguments.require_hardware:
        for item in HARDWARE_EVIDENCE:
            if scalar(qualification, "evidence", item, "status") != "passed":
                failures.append(f"required hardware evidence is not passed: {item}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    suffix = ""
    if arguments.require_hardware:
        suffix = " and required software and hardware are recorded"
    elif arguments.require_software:
        suffix = " and required software is recorded"
    print("Release inputs are internally consistent" + suffix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
