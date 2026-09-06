#!/usr/bin/env python3
"""Convert Gradle text dependency reports into a selected-component CycloneDX SBOM."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import quote


DEPENDENCY = re.compile(r"[+\\]---\s+([^\s:]+):([^\s:]+):(.+?)\s*$")
ANNOTATION = re.compile(r"\s+\([^)]*\)\s*$")


def selected_version(raw: str) -> str | None:
    """Extract the selected version from one Gradle dependency-tree value."""
    value = raw.rsplit(" -> ", maxsplit=1)[-1]
    while ANNOTATION.search(value):
        value = ANNOTATION.sub("", value)
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        strict = re.fullmatch(r"\{strictly\s+([^;}]+)(?:;[^}]*)?\}", value)
        value = strict.group(1).strip() if strict else ""
    if not value or value in {"FAILED", "(*)", "(c)", "(n)"}:
        return None
    return value


def components(paths: list[Path]) -> list[dict[str, str]]:
    """Return sorted, unique Maven components selected by Gradle."""
    selected: set[tuple[str, str, str]] = set()
    for path in paths:
        for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
            match = DEPENDENCY.search(line)
            if not match:
                continue
            group, name, raw_version = match.groups()
            version = selected_version(raw_version)
            if version is not None:
                selected.add((group, name, version))
    result: list[dict[str, str]] = []
    for group, name, version in sorted(selected):
        purl = (
            f"pkg:maven/{quote(group, safe='.-_')}/{quote(name, safe='.-_')}"
            f"@{quote(version, safe='.-_+') }"
        )
        result.append(
            {
                "type": "library",
                "bom-ref": purl,
                "group": group,
                "name": name,
                "version": version,
                "purl": purl,
            }
        )
    return result


def main() -> None:
    """Parse command-line inputs and write a deterministic CycloneDX document."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path, help="Gradle dependency report files")
    parser.add_argument("--output", required=True, type=Path, help="CycloneDX JSON output")
    arguments = parser.parse_args()
    missing = [str(path) for path in arguments.reports if not path.is_file()]
    if missing:
        parser.error("missing report files: " + ", ".join(missing))
    resolved = components(arguments.reports)
    if not resolved:
        parser.error("no selected Maven components were found")
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "desfire-sdk-gradle-build-graph",
            },
            "properties": [
                {"name": "desfire:graph-scope", "value": "build-and-runtime"},
                {"name": "desfire:component-count", "value": str(len(resolved))},
            ],
        },
        "components": resolved,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {len(resolved)} selected Maven components to {arguments.output}")


if __name__ == "__main__":
    main()
