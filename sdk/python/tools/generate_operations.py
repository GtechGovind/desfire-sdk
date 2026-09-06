"""Generate checked managed-operation wrappers from the split C99 ABI headers."""

from __future__ import annotations

import argparse
import hashlib
import json
import pprint
import re
from pathlib import Path

_LIFECYCLE = {"df_open", "df_close", "df_reset", "df_cancel", "df_notify_state_change"}
_HAND_WRITTEN = {"df_set_picc_configuration", "df_execute_transaction"}
_FRIENDLY_OVERRIDES = {
    "df_authenticate_standard_aes",
    "df_authenticate_ev2_first_aes",
    "df_authenticate_ev2_first_aes_with_capabilities",
    "df_authenticate_ev2_non_first_aes",
    "df_authenticate_iso_aes",
}


def _declarations(header: str) -> list[tuple[str, list[str]]]:
    """Return exported int32 declarations after removing comments and normalizing whitespace."""
    clean = re.sub(r"/\*.*?\*/", "", header, flags=re.S)
    declarations: list[tuple[str, list[str]]] = []
    for name, arguments in re.findall(r"DF_API\s+int32_t\s+(df_\w+)\s*\((.*?)\)\s*;", clean, re.S):
        declarations.append((name, [" ".join(value.split()) for value in arguments.split(",")]))
    return declarations


def _operation(name: str, declaration: list[str]) -> tuple[list[tuple[str, str]], str] | None:
    """Map one managed C declaration to safe generic marshal kinds, or choose handwritten code."""
    if name in _LIFECYCLE or name in _HAND_WRITTEN or name.endswith("_provider"):
        return None
    if not declaration or not re.match(r"df_card\s+\w+$", declaration[0]):
        return None
    if declaration[-1] != "df_error* error":
        raise ValueError(f"{name} does not end with df_error* error")
    parameters = declaration[1:-1]
    output = "void"
    output_types = {
        "df_buffer**": "bytes",
        "uint32_t*": "u32",
        "int32_t*": "i32",
        "df_authentication_info_v1*": "authentication_info",
        "df_delegated_application_info_v1*": "delegated_application_info",
    }
    if parameters:
        candidate_type = parameters[-1].rsplit(" ", 1)[0]
        if candidate_type in output_types:
            output = output_types[candidate_type]
            parameters.pop()
    mapped: list[tuple[str, str]] = []
    index = 0
    while index < len(parameters):
        parameter = parameters[index]
        ctype, argument = parameter.rsplit(" ", 1)
        if ctype == "const uint8_t*":
            if index + 1 >= len(parameters):
                raise ValueError(f"Unpaired byte pointer in {name}")
            size_type, _ = parameters[index + 1].rsplit(" ", 1)
            if size_type != "size_t":
                raise ValueError(f"Unpaired byte pointer in {name}")
            mapped.append((argument, "bytes"))
            index += 2
            continue
        kind = {"uint32_t": "u32", "int32_t": "i32"}.get(ctype)
        if kind is None:
            raise ValueError(f"Unsupported managed ABI type in {name}: {parameter}")
        mapped.append((argument, kind))
        index += 1
    return mapped, output


def _render(root: Path) -> str:
    """Render deterministic operation metadata and thin methods from managed.h."""
    header = (root / "c-api/include/desfire/managed.h").read_text()
    operations: list[tuple[str, list[tuple[str, str]], str]] = []
    for name, declaration in _declarations(header):
        mapped = _operation(name, declaration)
        if mapped is not None:
            operations.append((name, mapped[0], mapped[1]))
    lines = [
        '"""Generated from split C headers; do not hand-edit."""',
        "",
        "from typing import Any, Callable, cast, Union",
        "",
        "Binary = Union[bytes, bytearray, memoryview]",
        "",
        "# Each tuple contains (parameter name, ABI marshal kind).",
        "FUNCTIONS: dict[str, tuple[tuple[tuple[str, str], ...], str]] = {",
    ]
    methods: list[str] = []
    for name, parameters, output in operations:
        lines.append(f"    {name!r}: (")
        formatted = pprint.pformat(tuple(parameters), width=92, compact=True)
        for line in formatted.splitlines():
            lines.append("        " + line)
        lines[-1] += ","
        lines.append(f"        {output!r},")
        lines.append("    ),")
        if name in _FRIENDLY_OVERRIDES:
            continue
        result_type = {
            "void": "None",
            "bytes": "bytes",
            "u32": "int",
            "i32": "int",
            "authentication_info": "Any",
            "delegated_application_info": "Any",
        }[output]
        signature: list[str] = []
        for argument, kind in parameters:
            annotation = "Binary" if kind == "bytes" else "int"
            default = " = 5000" if argument == "timeout_ms" else ""
            signature.append(f"{argument}: {annotation}{default}")
        methods.extend(["", f"    def {name.removeprefix('df_')}(", "        self,"])
        methods.extend(f"        {argument}," for argument in signature)
        methods.extend(
            [
                f"    ) -> {result_type}:",
                (
                    f'        """Invoke ``{name}`` once and preserve its result and '
                    'delivery evidence."""'
                ),
                f"        return cast({result_type}, self._invoke({name!r}, (",
            ]
        )
        methods.extend(f"            {argument}," for argument, _ in parameters)
        methods.append("        )))")
    lines.extend(
        [
            "}",
            "",
            "",
            "class Operations:",
            '    """Complete direct-key managed C operations with Python-owned results."""',
            "",
            "    _invoke: Callable[[str, tuple[Any, ...]], Any]",
            *methods,
            "",
        ]
    )
    return "\n".join(lines)


def _inventory(root: Path) -> str:
    """Render the Python ABI inventory and prove manifest-to-header symbol parity."""
    document = json.loads((root / "api/ev3-api.json").read_text())
    canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(canonical).hexdigest()
    header_symbols: set[str] = set()
    for header in (root / "c-api/include").rglob("*.h"):
        header_symbols.update(
            re.findall(r"DF_API\s+[^;]*?\b(df_\w+)\s*\(", header.read_text(), re.S)
        )
    utility_symbols = {
        "df_abi_version",
        "df_manifest_sha256",
        "df_buffer_size",
        "df_buffer_data",
        "df_buffer_free",
    }
    manifest_symbols = {operation["cSymbol"] for operation in document["operations"]}
    if manifest_symbols | utility_symbols != header_symbols:
        missing = sorted(header_symbols - manifest_symbols - utility_symbols)
        extra = sorted(manifest_symbols - header_symbols)
        raise ValueError(f"Manifest/header symbol mismatch; missing={missing}, extra={extra}")
    lines = [
        '"""Generated ABI operation inventory; do not edit."""',
        "",
        f"ABI_VERSION = {document['abiVersion']}",
        f'MANIFEST_SHA256 = "{digest}"',
        "OPERATIONS = {",
    ]
    for operation in document["operations"]:
        lines.append(
            f"    {operation['id']}: ({operation['name']!r}, {operation['cSymbol']!r}, "
            f"{operation['surface']!r}),"
        )
    lines.extend(["}", ""])
    return "\n".join(lines)


def generate(check: bool = False) -> None:
    """Write generated bindings or fail when the checked-in output differs."""
    package = Path(__file__).resolve().parents[1]
    root = package.parents[1]
    outputs = {
        package / "src/desfire_ev3/_operations.py": _render(root),
        package / "src/desfire_ev3/raw/operations_generated.py": _inventory(root),
    }
    if check:
        stale = [
            path
            for path, content in outputs.items()
            if not path.exists() or path.read_text() != content
        ]
        if stale:
            raise SystemExit("Python bindings are stale; run tools/generate_operations.py")
        return
    for destination, generated in outputs.items():
        destination.write_text(generated)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check output without writing it")
    generate(parser.parse_args().check)
