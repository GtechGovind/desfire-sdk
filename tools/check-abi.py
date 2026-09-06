#!/usr/bin/env python3
"""Verify the ABI-v1 symbol baseline, platform allowlists, and an optional built library."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER_ROOT = ROOT / "c-api" / "include"
BASELINE = ROOT / "c-api" / "abi" / "abi-v1.symbols"


def header_symbols() -> set[str]:
    """Return every function declared with public C visibility."""
    pattern = re.compile(r"\bDF_API\s+[^;()]+?\s+(df_[a-z0-9_]+)\s*\(")
    return {
        symbol
        for header in HEADER_ROOT.rglob("*.h")
        for symbol in pattern.findall(header.read_text(errors="replace"))
    }


def baseline_symbols() -> set[str]:
    """Read non-comment symbols from the canonical ABI baseline."""
    return {
        line.strip()
        for line in BASELINE.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def allowlist_symbols(path: pathlib.Path) -> set[str]:
    """Decode one Mach-O, ELF, or PE export-control file."""
    text = path.read_text()
    if path.suffix == ".exports":
        return {line.strip().removeprefix("_") for line in text.splitlines() if line.strip()}
    return set(re.findall(r"\b(df_[a-z0-9_]+)\b", text))


def library_symbols(path: pathlib.Path) -> set[str]:
    """Read externally defined df_* symbols from one native shared library."""
    if sys.platform == "darwin":
        command = ["nm", "-gU", str(path)]
    else:
        command = ["nm", "-D", "--defined-only", str(path)]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "nm failed")
    return {
        match.group(1)
        for line in completed.stdout.splitlines()
        if (match := re.search(r"\b_?(df_[a-z0-9_]+)$", line.strip()))
    }


def difference(label: str, expected: set[str], actual: set[str]) -> list[str]:
    """Describe missing and unexpected symbols for one checked source."""
    return [
        *(f"{label} is missing {symbol}" for symbol in sorted(expected - actual)),
        *(f"{label} unexpectedly exports {symbol}" for symbol in sorted(actual - expected)),
    ]


def main() -> int:
    """Validate all tracked symbol lists and optionally the linked library."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=pathlib.Path, help="optional built shared library")
    arguments = parser.parse_args()
    expected = baseline_symbols()
    failures = difference("C headers", expected, header_symbols())
    for relative in (
        "c-api/exports/macos.exports",
        "c-api/exports/linux.map",
        "c-api/exports/windows.def",
    ):
        failures.extend(difference(relative, expected, allowlist_symbols(ROOT / relative)))
    if arguments.library:
        try:
            failures.extend(
                difference(str(arguments.library), expected, library_symbols(arguments.library)))
        except RuntimeError as error:
            failures.append(str(error))
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {len(expected)} ABI-v1 symbols")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
