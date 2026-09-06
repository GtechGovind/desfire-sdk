#!/usr/bin/env python3
"""Generate language-neutral operation inventories from the canonical EV3 API manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "api" / "ev3-api.json"
HASH_FILE = ROOT / "api" / "ev3-api.sha256"


def canonical_bytes(document: dict[str, object]) -> bytes:
    """Return the stable JSON byte sequence used as the cross-language identity."""
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def python_inventory(document: dict[str, object], digest: str) -> str:
    """Render immutable Python raw-operation metadata without protocol encoding."""
    operations = document["operations"]
    lines = [
        '"""Generated ABI operation inventory; do not edit."""',
        "",
        f"ABI_VERSION = {document['abiVersion']}",
        f'MANIFEST_SHA256 = "{digest}"',
        "OPERATIONS = {",
    ]
    for operation in operations:
        lines.append(
            f"    {operation['id']}: ({operation['name']!r}, {operation['cSymbol']!r}, "
            f"{operation['surface']!r}),"
        )
    lines.extend(["}", ""])
    return "\n".join(lines)


def typescript_inventory(document: dict[str, object], digest: str) -> str:
    """Render strict TypeScript raw-operation metadata without wire construction."""
    lines = [
        "/** Generated ABI operation inventory; do not edit. */",
        f"export const ABI_VERSION = {document['abiVersion']} as const;",
        f'export const MANIFEST_SHA256 = "{digest}" as const;',
        "export const OPERATIONS = {",
    ]
    for operation in document["operations"]:
        lines.append(
            f"  {operation['id']}: {{ name: \"{operation['name']}\", "
            f"symbol: \"{operation['cSymbol']}\", surface: \"{operation['surface']}\" }},"
        )
    lines.extend(["} as const;", ""])
    return "\n".join(lines)


def javascript_inventory(document: dict[str, object], digest: str) -> str:
    """Render immutable ESM operation metadata for the published Node package."""
    lines = [
        "/** Generated ABI operation inventory; do not edit. */",
        f"export const ABI_VERSION = {document['abiVersion']};",
        f'export const MANIFEST_SHA256 = "{digest}";',
        "export const OPERATIONS = Object.freeze({",
    ]
    for operation in document["operations"]:
        lines.append(
            f"  {operation['id']}: Object.freeze({{ name: \"{operation['name']}\", "
            f"symbol: \"{operation['cSymbol']}\", surface: \"{operation['surface']}\" }}),"
        )
    lines.extend(["});", ""])
    return "\n".join(lines)


def kotlin_inventory(document: dict[str, object], digest: str) -> str:
    """Render Kotlin raw-operation metadata without APDU or native-frame encoding."""
    lines = [
        "// Generated ABI operation inventory; do not edit.",
        "package com.desfire.ev3.raw",
        "",
        "/** Stable operation identity used by JNI manifest verification and raw dispatch. */",
        "public data class RawOperation(",
        "    public val id: Int,",
        "    public val name: String,",
        "    public val symbol: String,",
        "    public val surface: String,",
        ")",
        "",
        f"public const val ABI_VERSION: Int = {document['abiVersion']}",
        f'public const val MANIFEST_SHA256: String = "{digest}"',
        "public val OPERATIONS: Map<Int, RawOperation> = listOf(",
    ]
    for operation in document["operations"]:
        lines.append(
            f'    RawOperation({operation["id"]}, "{operation["name"]}", '
            f'"{operation["cSymbol"]}", "{operation["surface"]}"),'
        )
    lines.extend([").associateBy(RawOperation::id)", ""])
    return "\n".join(lines)


def swift_inventory(document: dict[str, object], digest: str) -> str:
    """Render Swift raw-operation metadata without card-protocol implementation."""
    lines = [
        "// Generated ABI operation inventory; do not edit.",
        "import Foundation",
        "",
        "/// Stable operation identity used by native manifest verification and raw dispatch.",
        "public struct RawOperation: Sendable, Hashable {",
        "    public let id: UInt32",
        "    public let name: String",
        "    public let symbol: String",
        "    public let surface: String",
        "}",
        "",
        f"public let desfireAbiVersion: UInt32 = {document['abiVersion']}",
        f'public let desfireManifestSha256 = "{digest}"',
        "public let desfireRawOperations: [RawOperation] = [",
    ]
    for operation in document["operations"]:
        lines.append(
            f'    RawOperation(id: {operation["id"]}, name: "{operation["name"]}", '
            f'symbol: "{operation["cSymbol"]}", surface: "{operation["surface"]}"),'
        )
    lines.extend(["]", ""])
    return "\n".join(lines)


def cpp_inventory(document: dict[str, object], digest: str) -> str:
    """Render a C++ include used by native binding loaders to check identity."""
    lines = [
        "// Generated ABI operation inventory; do not edit.",
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstdint>",
        "#include <string_view>",
        "",
        "namespace desfire::bindings::generated {",
        "    struct Operation final {",
        "        std::uint32_t id;",
        "        std::string_view name;",
        "        std::string_view symbol;",
        "        std::string_view surface;",
        "    };",
        "",
        f"    inline constexpr std::uint32_t abi_version = {document['abiVersion']};",
        "    inline constexpr std::string_view manifest_sha256 =",
        f'        "{digest}";',
        f"    inline constexpr std::array<Operation, {len(document['operations'])}> operations{{{{",
    ]
    for operation in document["operations"]:
        fields = [
            str(operation["id"]),
            f'"{operation["name"]}"',
            f'"{operation["cSymbol"]}"',
            f'"{operation["surface"]}"',
        ]
        operation_lines = ["        {"]
        for index, field in enumerate(fields):
            suffix = "}," if index == len(fields) - 1 else ","
            candidate = operation_lines[-1] + field + suffix
            if len(candidate) <= 100:
                operation_lines[-1] = candidate
            else:
                operation_lines.append("         " + field + suffix)
            if index != len(fields) - 1:
                operation_lines[-1] += " "
        lines.extend(line.rstrip() for line in operation_lines)
    lines.extend(["    }};", "} // namespace desfire::bindings::generated", ""])
    return "\n".join(lines)


def outputs(document: dict[str, object], digest: str) -> dict[pathlib.Path, str]:
    """Return every generated inventory and its deterministic contents."""
    return {
        ROOT / "sdk/python/src/desfire_ev3/raw/operations_generated.py": python_inventory(
            document, digest
        ),
        ROOT / "sdk/node/src/raw/operations.generated.ts": typescript_inventory(document, digest),
        ROOT / "sdk/node/src/raw/operations.generated.mjs": javascript_inventory(document, digest),
        ROOT
        / "sdk/kotlin/src/main/kotlin/com/desfire/ev3/raw/RawOperations.generated.kt": kotlin_inventory(
            document, digest
        ),
        ROOT
        / "sdk/apple/Sources/DesfireEV3/Raw/GeneratedOperations.swift": swift_inventory(
            document, digest
        ),
        ROOT / "sdk/generated/operation_manifest.generated.hpp": cpp_inventory(document, digest),
    }


def update(path: pathlib.Path, content: str, check: bool) -> bool:
    """Write one generated file, or report whether the checked-in copy is current."""
    expected = content.encode()
    if check:
        return path.exists() and path.read_bytes() == expected
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)
    return True


def main() -> int:
    """Generate every inventory or fail when any generated file/hash has drifted."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check files without modifying them")
    arguments = parser.parse_args()

    document = json.loads(MANIFEST.read_text())
    digest = hashlib.sha256(canonical_bytes(document)).hexdigest()
    stale = [
        path.relative_to(ROOT)
        for path, content in outputs(document, digest).items()
        if not update(path, content, arguments.check)
    ]
    if arguments.check:
        if not HASH_FILE.exists() or HASH_FILE.read_text().strip() != digest:
            stale.append(HASH_FILE.relative_to(ROOT))
        if stale:
            print("Generated binding files are stale:", file=sys.stderr)
            print("\n".join(str(path) for path in stale), file=sys.stderr)
            return 1
    else:
        HASH_FILE.write_text(digest + "\n")
    print(f"Generated {len(outputs(document, digest))} inventories for {len(document['operations'])} operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
