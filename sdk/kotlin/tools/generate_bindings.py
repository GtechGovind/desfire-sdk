#!/usr/bin/env python3
"""Regenerate canonical inventories and validate the typed Kotlin/JNI surface."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
KOTLIN = ROOT / "sdk/kotlin"
GENERATOR = ROOT / "tools/generate-bindings.py"


def main() -> int:
    """Delegate inventories to the canonical manifest generator and reject stale API layouts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check generated inventories")
    arguments = parser.parse_args()
    command = [sys.executable, str(GENERATOR)]
    if arguments.check:
        command.append("--check")
    subprocess.run(command, cwd=ROOT, check=True)

    required = {
        "src/main/kotlin/com/desfire/ev3/Authentication.kt": (
            "authenticateStandardAes",
            "authenticateEv2FirstAes",
            "authenticateEv2NonFirstAes",
            "authenticateIsoAes",
        ),
        "src/main/kotlin/com/desfire/ev3/BlockingCard.kt": ("class BlockingCard",),
        "src/main/kotlin/com/desfire/ev3/Card.kt": ("class Card",),
        "src/main/kotlin/com/desfire/ev3/raw/RawOperations.generated.kt": (
            "MANIFEST_SHA256",
        ),
        "src/main/cpp/operations.inc": ("df_reset_authentication", "df_execute_transaction"),
    }
    for relative, markers in required.items():
        path = KOTLIN / relative
        source = path.read_text()
        missing = [marker for marker in markers if marker not in source]
        if missing:
            raise RuntimeError(f"{relative} lacks current API markers: {missing}")

    forbidden = ("kotlin" + "-host", "df_authenticate" + "_aes", "Ev3" + "Card", "Suspending" + "Ev3" + "Card")
    for path in KOTLIN.rglob("*"):
        if not path.is_file() or any(part in {"build", ".gradle"} for part in path.parts):
            continue
        source = path.read_text(errors="ignore")
        stale = [marker for marker in forbidden if marker in source]
        if stale:
            raise RuntimeError(f"{path.relative_to(ROOT)} contains stale markers: {stale}")
    print("Kotlin typed API and JNI markers match the canonical manifest layout")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
