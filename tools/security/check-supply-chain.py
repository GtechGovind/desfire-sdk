#!/usr/bin/env python3
"""Validate repository-owned supply-chain controls without third-party packages."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml


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
WRAPPER_JAR_SHA256 = "497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7"
WRAPPER_DISTRIBUTION_SHA256 = (
    "bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01"
)
WRAPPER_URL = "https\\://services.gradle.org/distributions/gradle-9.6.0-bin.zip"
CODSPEED_CPP_REVISION = "f5a917fdd14db7293bd37acb682873fec19f8b6c"
CODSPEED_CPP_SHA256 = "fe8f8a5f61ef0464df9fd3349491c358fdaa023d6cc17e3ca8d3cc6cd09c1634"
CODSPEED_ACTION_REVISION = "373d6868929f444bc08d901fd0eb0ad52a8875ea"


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
        failures.append("Gradle wrapper JAR differs from the reviewed Gradle 9.6.0 wrapper")
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
        document = path.read_bytes()
        if b"<!DOCTYPE" in document.upper() or b"<!ENTITY" in document.upper():
            failures.append(f"{path}: DTD and entity declarations are prohibited")
            return
        root = ET.fromstring(document)
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


def validate_codspeed(failures: list[str]) -> None:
    """Require immutable, checksum-verified CodSpeed C++ inputs and tokenless public upload."""
    module_path = ROOT / "cmake" / "DesfireCodSpeed.cmake"
    workflow_path = WORKFLOW_DIRECTORY / "codspeed.yml"
    if not module_path.is_file():
        failures.append(f"missing CodSpeed dependency module: {module_path}")
        return
    if not workflow_path.is_file():
        failures.append(f"missing CodSpeed workflow: {workflow_path}")
        return

    module = module_path.read_text(encoding="utf-8")
    required_module_values = (
        CODSPEED_CPP_REVISION,
        "codspeed-cpp/releases/download/v2.4.0/codspeed-cpp-v2.4.0.tar.gz",
        f"SHA256={CODSPEED_CPP_SHA256}",
        "google_benchmark-src/core/instrument-hooks",
    )
    for value in required_module_values:
        if value not in module:
            failures.append(f"{module_path}: missing pinned CodSpeed input {value}")
    if "GIT_TAG" in module:
        failures.append(f"{module_path}: CodSpeed inputs must use checksum-verified archives")

    workflow = workflow_path.read_text(encoding="utf-8")
    action_reference = f"CodSpeedHQ/action@{CODSPEED_ACTION_REVISION}"
    if action_reference not in workflow:
        failures.append(f"{workflow_path}: CodSpeed action must equal {action_reference}")
    if re.search(r"(?m)^\s*token:\s*", workflow):
        failures.append(f"{workflow_path}: public CodSpeed upload must remain tokenless")
    if "-DCODSPEED_MODE=simulation" not in workflow or "mode: simulation" not in workflow:
        failures.append(f"{workflow_path}: CodSpeed simulation must be enabled at build and upload")
    if "runner-version: 5.2.1" not in workflow or "cache-instruments: false" not in workflow:
        failures.append(f"{workflow_path}: CodSpeed runner and cache policy must remain pinned")


def validate_windows_library_staging(failures: list[str]) -> None:
    """Require Windows tests to resolve the exact C ABI library built by their job."""
    workflow_path = WORKFLOW_DIRECTORY / "native.yml"
    if not workflow_path.is_file():
        failures.append(f"missing native workflow: {workflow_path}")
        return
    workflow = workflow_path.read_text(encoding="utf-8")
    if "runner: windows-2025-vs2026" not in workflow:
        failures.append(f"{workflow_path}: Windows native tests must use the VS 2026 image")
    required_paths = (
        "c-api/Release/desfire_c.dll",
        "tests/Release/desfire_c.dll",
        "examples/Release/desfire_c.dll",
        "bin/desfire_c.dll",
        "consumer-windows-cxx${{ matrix.standard }}/Release/desfire_c.dll",
    )
    for value in required_paths:
        if value not in workflow:
            failures.append(f"{workflow_path}: missing Windows C ABI staging path {value}")
    if workflow.count("cmake -E copy_if_different") != 3:
        failures.append(f"{workflow_path}: expected three deterministic Windows DLL copies")


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
    validate_codspeed(failures)
    validate_windows_library_staging(failures)
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    print("Supply-chain policy checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
