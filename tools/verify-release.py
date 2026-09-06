#!/usr/bin/env python3
"""Verify release inputs without promoting missing hardware evidence to a pass."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(command: list[str]) -> list[str]:
    """Run one deterministic repository check and return a concise failure description."""
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if completed.returncode == 0:
        return []
    detail = (completed.stderr or completed.stdout).strip()
    return [f"{' '.join(command)} failed: {detail}"]


def main() -> int:
    """Check manifests, required packaging inputs, and optionally qualification evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-hardware",
        action="store_true",
        help="fail unless physical EV3, reader, Android NFC, and iOS NFC are recorded as passed",
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
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        failures.append("api/ev3-api.sha256 is not a SHA-256 digest")

    manifest_digest = hashlib.sha256((ROOT / "api" / "ev3-api.json").read_bytes()).hexdigest()
    if manifest_digest == digest:
        failures.append("API identity must hash canonical JSON, not incidental file formatting")

    if arguments.require_hardware:
        qualification = (ROOT / "spec" / "qualification-record.yaml").read_text()
        for item in ("android_physical_nfc", "ios_physical_nfc", "physical_ev3_card", "pcsc_reader"):
            match = re.search(rf"^\s{{2}}{item}:\s*\n\s{{4}}status:\s*([^\s]+)", qualification,
                              re.MULTILINE)
            if not match or match.group(1) != "passed":
                failures.append(f"required hardware evidence is not passed: {item}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Release inputs are internally consistent" +
          (" and required hardware is recorded" if arguments.require_hardware else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
