#!/usr/bin/env python3
"""Validate that the EV3 coverage record names real tests and explicit exclusions."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "spec" / "ev3-command-coverage.yaml"
TEST_CMAKE = ROOT / "tests" / "CMakeLists.txt"


def listed_tests(text: str) -> set[str]:
    """Extract test identifiers from YAML flow sequences without adding a YAML dependency."""
    result: set[str] = set()
    for match in re.finditer(r"tests:\s*\[([^]]*)]", text, re.MULTILINE):
        result.update(item.strip() for item in match.group(1).split(",") if item.strip())
    return result


def configured_tests(text: str) -> set[str]:
    """Extract CTest executable names created by the repository test helper."""
    names = set(re.findall(r"\b(?:df|desfire)_test\(\s*([a-zA-Z0-9_]+)", text))
    names.update(re.findall(r"\badd_test\(\s*NAME\s+([a-zA-Z0-9_]+)", text))
    return names


def main() -> int:
    """Reject stale test references, duplicate exclusions, and unsupported API placeholders."""
    coverage = COVERAGE.read_text()
    cmake = TEST_CMAKE.read_text()
    failures: list[str] = []

    missing = listed_tests(coverage) - configured_tests(cmake)
    failures.extend(f"coverage references an unconfigured test: {name}" for name in sorted(missing))

    unsupported = re.findall(r"^\s+- feature:\s*([a-z0-9_]+)\s*$", coverage, re.MULTILINE)
    duplicates = sorted({name for name in unsupported if unsupported.count(name) > 1})
    failures.extend(f"duplicate unsupported feature: {name}" for name in duplicates)
    if not unsupported:
        failures.append("coverage must retain an explicit unsupported section")

    forbidden = (ROOT / "core" / "include").rglob("*.hpp")
    for header in forbidden:
        content = header.read_text(errors="replace")
        for feature in unsupported:
            token = feature.replace("_", "")
            if token == "sdm" and re.search(r"\b(?:create|configure|enable)_?sdm\b", content, re.I):
                failures.append(f"unsupported SDM provisioning API appears in {header.relative_to(ROOT)}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {len(listed_tests(coverage))} coverage test references and "
          f"{len(unsupported)} explicit exclusions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
