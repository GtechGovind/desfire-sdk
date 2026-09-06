#!/usr/bin/env python3
"""Validate the canonical EV3 API manifest against the exported C headers."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "api" / "ev3-api.json"
HASH_FILE = ROOT / "api" / "ev3-api.sha256"
HEADER_ROOT = ROOT / "c-api" / "include"
SYMBOL = re.compile(r"\bDF_API\s+int32_t\s+(df_[a-z0-9_]+)\s*\(")
NAME = re.compile(r"^[a-z][a-z0-9_]*$")


def exported_operations() -> set[str]:
    """Read every installed C header so a split umbrella cannot hide operations."""
    symbols: set[str] = set()
    for header in sorted(HEADER_ROOT.rglob("*.h")):
        symbols.update(SYMBOL.findall(header.read_text(errors="replace")))
    return symbols


def canonical_bytes(document: dict[str, object]) -> bytes:
    """Serialize the manifest deterministically for generated-binding identity checks."""
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(document: dict[str, object]) -> list[str]:
    """Return actionable structural and C-export parity errors."""
    failures: list[str] = []
    if document.get("schemaVersion") != 1:
        failures.append("schemaVersion must be 1")
    if not isinstance(document.get("abiVersion"), int) or document["abiVersion"] < 1:
        failures.append("abiVersion must be a positive integer")
    operations = document.get("operations")
    if not isinstance(operations, list):
        return [*failures, "operations must be an array"]

    ids: set[int] = set()
    names: set[str] = set()
    symbols: set[str] = set()
    for index, value in enumerate(operations):
        prefix = f"operations[{index}]"
        if not isinstance(value, dict):
            failures.append(f"{prefix} must be an object")
            continue
        operation_id = value.get("id")
        name = value.get("name")
        symbol = value.get("cSymbol")
        if not isinstance(operation_id, int) or operation_id <= 0:
            failures.append(f"{prefix}.id must be a positive integer")
        elif operation_id in ids:
            failures.append(f"duplicate operation id {operation_id}")
        else:
            ids.add(operation_id)
        if not isinstance(name, str) or not NAME.fullmatch(name):
            failures.append(f"{prefix}.name is invalid")
        elif name in names:
            failures.append(f"duplicate operation name {name}")
        else:
            names.add(name)
        if not isinstance(symbol, str) or not symbol.startswith("df_"):
            failures.append(f"{prefix}.cSymbol is invalid")
        elif symbol in symbols:
            failures.append(f"duplicate C symbol {symbol}")
        else:
            symbols.add(symbol)
        for required in ("coreOperation", "domain", "surface", "summary", "documentation",
                         "mutation", "deliveryRules", "sessionEffect", "parameters", "result"):
            if required not in value:
                failures.append(f"{prefix}.{required} is required")
        rules = value.get("deliveryRules")
        if not isinstance(rules, list) or not rules or not all(isinstance(rule, str) for rule in rules):
            failures.append(f"{prefix}.deliveryRules must be a nonempty string array")

    exported = exported_operations()
    missing_headers = symbols - exported
    missing_manifest = exported - symbols
    failures.extend(f"manifest symbol is not exported: {item}" for item in sorted(missing_headers))
    failures.extend(f"exported operation is absent from manifest: {item}" for item in sorted(missing_manifest))
    return failures


def main() -> int:
    """Check manifest structure/parity and optionally refresh its deterministic hash."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="also require the stored hash")
    parser.add_argument("--write-hash", action="store_true", help="write the canonical hash")
    arguments = parser.parse_args()
    document = json.loads(MANIFEST.read_text())
    failures = validate(document)
    digest = hashlib.sha256(canonical_bytes(document)).hexdigest()
    if arguments.write_hash:
        HASH_FILE.write_text(digest + "\n")
    if arguments.check:
        if not HASH_FILE.exists() or HASH_FILE.read_text().strip() != digest:
            failures.append("ev3-api.sha256 is missing or stale")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {len(document['operations'])} ABI operations; manifest sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
