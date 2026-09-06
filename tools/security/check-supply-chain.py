#!/usr/bin/env python3
"""Validate repository-owned supply-chain controls without third-party packages."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
ACTION_REFERENCE = re.compile(r"(?m)^\s*uses:\s*([^\s#]+)")
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
CONTAINER_REFERENCE = re.compile(
    r"(?:docker\.io/)?(?:zricethezav/gitleaks|anchore/(?:syft|grype))"
    r"(?::[^\s\"']+)?(?:@sha256:[0-9a-f]{64})?"
    r"|ghcr\.io/google/osv-scanner-action"
    r"(?::[^\s\"']+)?(?:@sha256:[0-9a-f]{64})?"
)
WRAPPER_JAR_SHA256 = "7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172"
WRAPPER_DISTRIBUTION_SHA256 = (
    "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854"
)
WRAPPER_URL = "https\\://services.gradle.org/distributions/gradle-8.14.5-bin.zip"


def sha256(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_checkout_blocks(path: Path, content: str, failures: list[str]) -> None:
    """Require each checkout step to disable persisted GitHub credentials."""
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if "uses: actions/checkout@" not in line:
            continue
        indentation = len(line) - len(line.lstrip())
        block: list[str] = []
        for following in lines[index + 1 :]:
            stripped = following.lstrip()
            following_indentation = len(following) - len(stripped)
            if stripped.startswith("- ") and following_indentation <= indentation:
                break
            block.append(following)
        if not any(re.fullmatch(r"\s*persist-credentials:\s*false\s*", item) for item in block):
            failures.append(f"{path}: checkout must set persist-credentials: false")


def validate_workflows(failures: list[str]) -> None:
    """Check workflow permissions, immutable action references, and container digests."""
    workflows = sorted((*WORKFLOW_DIRECTORY.glob("*.yml"), *WORKFLOW_DIRECTORY.glob("*.yaml")))
    if not workflows:
        failures.append("no GitHub Actions workflows exist")
        return
    for path in workflows:
        content = path.read_text(encoding="utf-8")
        if "pull_request_target:" in content:
            failures.append(f"{path}: pull_request_target is prohibited")
        if not re.search(r"(?m)^permissions:\s*(?:\{\}|$)", content):
            failures.append(f"{path}: an explicit top-level permissions block is required")
        if re.search(r"(?m)^\s*permissions:\s*write-all\s*$", content):
            failures.append(f"{path}: write-all permissions are prohibited")
        if "--write-verification-metadata" in content:
            failures.append(f"{path}: workflows must not rewrite dependency verification metadata")

        for reference in ACTION_REFERENCE.findall(content):
            if reference.startswith("./"):
                continue
            if reference.startswith("docker://"):
                if not re.search(r"@sha256:[0-9a-f]{64}$", reference):
                    failures.append(f"{path}: container action is not digest-pinned: {reference}")
                continue
            if "@" not in reference:
                failures.append(f"{path}: action has no immutable reference: {reference}")
                continue
            revision = reference.rsplit("@", maxsplit=1)[1]
            if not FULL_COMMIT.fullmatch(revision):
                failures.append(f"{path}: action is not pinned to a full commit: {reference}")

        for reference in CONTAINER_REFERENCE.findall(content):
            if not re.search(r"@sha256:[0-9a-f]{64}$", reference):
                failures.append(f"{path}: scanner container is not digest-pinned: {reference}")
        validate_checkout_blocks(path, content, failures)


def load_properties(path: Path) -> dict[str, str]:
    """Load the small Gradle wrapper property file used by this repository."""
    properties: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f"invalid property line: {line}")
        properties[key] = value
    return properties


def validate_wrapper(failures: list[str]) -> None:
    """Verify the checked-in wrapper and its distribution checksum policy."""
    jar = ROOT / "gradle" / "wrapper" / "gradle-wrapper.jar"
    properties_path = ROOT / "gradle" / "wrapper" / "gradle-wrapper.properties"
    for path in (ROOT / "gradlew", ROOT / "gradlew.bat", jar, properties_path):
        if not path.is_file():
            failures.append(f"missing Gradle wrapper file: {path}")
            return
    if sha256(jar) != WRAPPER_JAR_SHA256:
        failures.append("Gradle wrapper JAR differs from the reviewed Gradle 8.14.5 wrapper")
    try:
        properties = load_properties(properties_path)
    except (OSError, ValueError) as error:
        failures.append(f"cannot read Gradle wrapper properties: {error}")
        return
    expected = {
        "distributionUrl": WRAPPER_URL,
        "distributionSha256Sum": WRAPPER_DISTRIBUTION_SHA256,
        "validateDistributionUrl": "true",
    }
    for key, value in expected.items():
        if properties.get(key) != value:
            failures.append(f"Gradle wrapper {key} must equal {value}")


def validate_verification_file(path: Path, failures: list[str]) -> None:
    """Require SHA-256 coverage for every recorded Gradle artifact."""
    if not path.is_file():
        failures.append(f"missing Gradle dependency verification metadata: {path}")
        return
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        failures.append(f"cannot parse {path}: {error}")
        return
    namespace = {"v": "https://schema.gradle.org/dependency-verification"}
    verify_metadata = root.findtext("v:configuration/v:verify-metadata", namespaces=namespace)
    if verify_metadata != "true":
        failures.append(f"{path}: verify-metadata must be true")
    components = root.findall("v:components/v:component", namespace)
    if not components:
        failures.append(f"{path}: no verified components are recorded")
    for artifact in root.findall("v:components/v:component/v:artifact", namespace):
        checksums = artifact.findall("v:sha256", namespace)
        if not checksums:
            failures.append(f"{path}: artifact {artifact.get('name')} has no SHA-256")
        for checksum in checksums:
            if not SHA256.fullmatch(checksum.get("value", "")):
                failures.append(f"{path}: artifact {artifact.get('name')} has an invalid SHA-256")


def validate_dependabot(failures: list[str]) -> None:
    """Require update coverage for every third-party package surface."""
    path = ROOT / ".github" / "dependabot.yml"
    if not path.is_file():
        failures.append("missing .github/dependabot.yml")
        return
    content = path.read_text(encoding="utf-8")
    for ecosystem in ("github-actions", "npm", "pip", "gradle", "swift"):
        if f'package-ecosystem: "{ecosystem}"' not in content:
            failures.append(f"Dependabot does not cover {ecosystem}")


def main() -> int:
    """Run all repository supply-chain policy checks."""
    failures: list[str] = []
    validate_workflows(failures)
    validate_wrapper(failures)
    validate_verification_file(
        ROOT / "sdk" / "android" / "gradle" / "verification-metadata.xml", failures
    )
    validate_verification_file(
        ROOT / "sdk" / "kotlin" / "gradle" / "verification-metadata.xml", failures
    )
    validate_dependabot(failures)
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    print("Supply-chain policy checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
