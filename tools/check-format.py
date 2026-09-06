#!/usr/bin/env python3
"""Check or apply the repository's C/C++ formatting without visiting local references."""

import argparse
import pathlib
import shutil
import subprocess
import sys


def main() -> int:
    """Visit source roots only, returning the first formatter failure to CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="Format files in place")
    parser.add_argument("--formatter", default="clang-format")
    args = parser.parse_args()
    formatter = shutil.which(args.formatter)
    if formatter is None and args.formatter == "clang-format":
        discovered = subprocess.run(
            ["xcrun", "-f", "clang-format"], text=True, capture_output=True, check=False
        )
        if discovered.returncode == 0:
            formatter = discovered.stdout.strip()
    if formatter is None:
        parser.error("clang-format was not found; pass --formatter /path/to/clang-format")
    root = pathlib.Path(__file__).resolve().parents[1]
    folders = ("foundation", "core", "sam", "providers", "transports", "plugin-host",
               "c-api", "sdk", "tests", "examples")
    extensions = {".h", ".hpp", ".c", ".cpp"}
    excluded = {"node_modules", "build", ".build", ".cxx", ".gradle"}
    # Explicit roots exclude restricted references, generated output, and unrelated
    # workspace files. No shell interpolation is used for filenames or tool paths.
    files = sorted(path for folder in folders for path in (root / folder).rglob("*")
                   if path.suffix in extensions and not excluded.intersection(path.parts))
    flags = ["-i"] if args.fix else ["--dry-run", "--Werror"]
    for path in files:
        result = subprocess.run([formatter, *flags, str(path)], cwd=root, check=False)
        if result.returncode:
            return result.returncode
    print(f"{'Formatted' if args.fix else 'Checked'} {len(files)} C/C++ files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
