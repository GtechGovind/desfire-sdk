#!/usr/bin/env python3
"""Reject remote GitHub Actions references that are not pinned to full commit SHAs."""

from __future__ import annotations

from pathlib import Path
import re
import sys


WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
PINNED = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)


def main() -> int:
    """Check every workflow use site while permitting repository-local actions."""
    failures: list[str] = []
    checked = 0
    for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
        for reference in USES.findall(workflow.read_text(encoding="utf-8")):
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            checked += 1
            if not PINNED.fullmatch(reference):
                failures.append(f"{workflow.name}: remote action is not SHA-pinned: {reference}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {checked} remote action references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
