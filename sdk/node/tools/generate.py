"""Generate the Node operation inventory, declarations, and N-API dispatch.

The repository API manifest is the source of truth. This generator only maps
already typed C ABI values; card protocol encoding remains in the C++ core.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys


RUNTIME = {"open", "close", "reset", "cancel", "notify_state_change",
           "raw_open", "raw_close", "raw_reset", "raw_cancel",
           "raw_notify_state_change"}

STRUCT_KINDS = {
    "picc_configuration": ("picc_configuration", "df_picc_configuration_v1"),
    "transaction_operations": ("transaction_plan", "df_transaction_operation_v1"),
    "native_request": ("native_request", "df_native_request_v1"),
    "native_secure_request": ("native_secure_request", "df_native_secure_request_v1"),
    "iso_apdu": ("iso_apdu", "df_iso_apdu_v1"),
    "delegated_application_configuration":
        ("delegated_application_configuration", "df_delegated_application_configuration_v1"),
}

TS_TYPES = {
    "u32": "number", "i32": "number", "boolean": "boolean", "bytes": "Uint8Array",
    "string": "string",
    "picc_configuration": "PiccConfiguration",
    "transaction_operations": "readonly TransactionOperation[]",
    "native_request": "NativeRequest", "native_secure_request": "NativeSecureRequest",
    "iso_apdu": "IsoApdu", "key_source": "KeySourceValue", "timeout": "TimeoutArgument",
    "delegated_application_configuration": "DelegatedApplicationConfiguration",
}

RESULT_TYPES = {
    "void": "void", "bytes": "Uint8Array", "uint32": "number", "int32": "number",
    "boolean": "boolean", "authentication_info": "AuthenticationInfo",
    "delegated_application_info": "DelegatedApplicationInfo",
    "native_response": "NativeResponse", "iso_response": "IsoResponse",
}

# Node resolves providers on the main event loop, then invokes the direct-key ABI
# operation in the worker. The manifest still records every provider C symbol.
PROVIDER_DIRECT = {
    "authenticate_standard_aes_provider": "authenticate_standard_aes",
    "authenticate_ev2_first_aes_provider": "authenticate_ev2_first_aes",
    "authenticate_ev2_first_aes_with_capabilities_provider":
        "authenticate_ev2_first_aes_with_capabilities",
    "authenticate_ev2_non_first_aes_provider": "authenticate_ev2_non_first_aes",
    "authenticate_iso_aes_provider": "authenticate_iso_aes",
    "set_default_aes_key_provider": "set_default_aes_key",
    "change_aes_key_provider": "change_aes_key",
    "create_transaction_mac_file_provider": "create_transaction_mac_file",
    "raw_authenticate_standard_aes_provider": "raw_authenticate_standard_aes",
    "raw_authenticate_ev2_first_aes_provider": "raw_authenticate_ev2_first_aes",
    "raw_authenticate_ev2_non_first_aes_provider": "raw_authenticate_ev2_non_first_aes",
    "raw_authenticate_iso_aes_provider": "raw_authenticate_iso_aes",
    "offline_derive_nxp_aes128_provider": "offline_derive_nxp_aes128",
    "offline_calculate_transaction_mac_aes_provider":
        "offline_calculate_transaction_mac_aes",
    "offline_encrypt_delegated_default_key_aes_provider":
        "offline_encrypt_delegated_default_key_aes",
    "offline_calculate_delegated_application_mac_aes_provider":
        "offline_calculate_delegated_application_mac_aes",
    "offline_calculate_delegated_application_delete_mac_aes_provider":
        "offline_calculate_delegated_application_delete_mac_aes",
    "offline_calculate_delegated_configuration_mac_aes_provider":
        "offline_calculate_delegated_configuration_mac_aes",
    "offline_calculate_mfc_license_mac_aes_provider":
        "offline_calculate_mfc_license_mac_aes",
    "offline_derive_transaction_mac_keys_aes_provider":
        "offline_derive_transaction_mac_keys_aes",
    "offline_verify_transaction_mac_aes_provider": "offline_verify_transaction_mac_aes",
}


def public_arguments(operation: dict) -> list[dict]:
    """Collapse C pointer/size pairs and remove handles, outputs, and errors."""
    result: list[dict] = []
    parameters = operation["parameters"]
    index = 0
    while index < len(parameters):
        parameter = parameters[index]
        semantic = parameter["semanticType"]
        if semantic in {"card_handle", "raw_channel_handle", "error", "output",
                        "authentication_info", "delegated_application_info",
                        "native_status", "iso_status", "boolean_output"}:
            index += 1
            continue
        if semantic == "size":
            index += 1
            continue
        if semantic == "key_provider":
            request = parameters[index + 1]
            if request["semanticType"] != "key_request":
                raise ValueError(f"Provider without request in {operation['name']}")
            result.append({"name": parameter["name"].removesuffix("_provider") + "_source",
                           "kind": "key_source"})
            index += 2
            continue
        if parameter["cType"] == "const uint8_t*":
            result.append({"name": parameter["name"], "kind": "bytes"})
            index += 2
            continue
        if semantic == "curve_name":
            result.append({"name": parameter["name"], "kind": "string"})
            index += 1
            continue
        if semantic in STRUCT_KINDS:
            result.append({"name": parameter["name"], "kind": semantic})
            index += 2 if semantic == "transaction_operations" else 1
            continue
        kind = "i32" if parameter["cType"] == "int32_t" else "u32"
        if semantic == "boolean":
            kind = "boolean"
        if semantic == "timeout":
            kind = "timeout"
        item = {"name": parameter["name"], "kind": kind}
        if "minimum" in parameter:
            item["minimum"] = parameter["minimum"]
        if "maximum" in parameter:
            item["maximum"] = parameter["maximum"]
        result.append(item)
        index += 1
    return result


def actual_result(operation: dict) -> str:
    """Infer scalar result labels from output pointers when needed."""
    if operation["result"] != "void":
        return operation["result"]
    for parameter in operation["parameters"]:
        if parameter["semanticType"] == "output":
            if parameter["cType"] == "int32_t*":
                return "int32"
            if parameter["cType"] == "uint32_t*":
                return "uint32"
    return "void"


def metadata(operation: dict) -> dict:
    """Return deterministic runtime metadata for one callable binding operation."""
    item = {
        "id": operation["id"], "native": operation["cSymbol"],
        "surface": operation["surface"], "arguments": public_arguments(operation),
        "output": actual_result(operation), "mutation": operation["mutation"],
        "summary": operation["summary"],
    }
    if operation["name"] in PROVIDER_DIRECT:
        item["providerDirect"] = PROVIDER_DIRECT[operation["name"]]
    return item


def cpp_input(parameter: dict, argument_index: int) -> tuple[list[str], list[str], int]:
    """Emit local conversion and C call expressions for one input parameter."""
    name = parameter["name"]
    semantic = parameter["semanticType"]
    if parameter["cType"] == "const uint8_t*":
        return ([f"auto {name} = binary(env, argument(env, arguments, {argument_index}));"],
                [f"{name}.data", f"{name}.size"], 2)
    if semantic == "curve_name":
        return ([f"auto {name} = string_value(env, argument(env, arguments, {argument_index}));"],
                [f"{name}.c_str()"], 1)
    if semantic in STRUCT_KINDS:
        helper, _ = STRUCT_KINDS[semantic]
        if semantic == "transaction_operations":
            return ([f"auto {name} = {helper}(env, argument(env, arguments, {argument_index}));"],
                    [f"{name}.values.data()", f"{name}.values.size()"], 2)
        return ([f"auto {name} = {helper}(env, argument(env, arguments, {argument_index}));"],
                [f"&{name}.value"], 2 if semantic == "transaction_operations" else 1)
    converter = "i32" if parameter["cType"] == "int32_t" else "u32"
    return ([f"auto {name} = {converter}(env, argument(env, arguments, {argument_index}));"],
            [name], 1)


def cpp_operation(operation: dict) -> list[str]:
    """Emit one checked C ABI branch for a non-provider operation."""
    args = public_arguments(operation)
    lines = [f'    if (operation == "{operation["cSymbol"]}") {{',
             f"        require_count(env, arguments, {len(args)});"]
    call: list[str] = []
    locals_: list[str] = []
    output_names: list[tuple[str, str, str]] = []
    argument_index = 0
    parameters = operation["parameters"]
    index = 0
    while index < len(parameters):
        parameter = parameters[index]
        semantic = parameter["semanticType"]
        ctype = parameter["cType"]
        name = parameter["name"]
        if semantic == "card_handle":
            call.append("context.card")
            index += 1
            continue
        if semantic == "raw_channel_handle":
            call.append("context.raw")
            index += 1
            continue
        if semantic == "error":
            call.append("&error")
            index += 1
            continue
        if semantic == "size":
            index += 1
            continue
        if semantic in {"key_provider", "key_request"}:
            raise ValueError(f"Provider operation reached C++ generation: {operation['name']}")
        if semantic in {"output", "authentication_info", "delegated_application_info",
                        "native_status", "iso_status", "boolean_output"}:
            if ctype == "df_buffer**":
                locals_.append(f"df_buffer* {name} = nullptr;")
                call.append(f"&{name}")
                output_names.append((name, "buffer", semantic))
            elif ctype == "df_authentication_info_v1*":
                locals_.append(f"df_authentication_info_v1 {name}{{}};")
                locals_.append(f"initialize_descriptor({name});")
                call.append(f"&{name}")
                output_names.append((name, "authentication", semantic))
            elif ctype == "df_delegated_application_info_v1*":
                locals_.append(f"df_delegated_application_info_v1 {name}{{}};")
                locals_.append(f"initialize_descriptor({name});")
                call.append(f"&{name}")
                output_names.append((name, "delegated", semantic))
            elif ctype == "uint32_t*":
                locals_.append(f"std::uint32_t {name}{{}};")
                call.append(f"&{name}")
                output_names.append((name, "u32", semantic))
            elif ctype == "int32_t*":
                locals_.append(f"std::int32_t {name}{{}};")
                call.append(f"&{name}")
                output_names.append((name, "i32", semantic))
            else:
                raise ValueError(f"Unsupported output {ctype} in {operation['name']}")
            index += 1
            continue
        emitted, expressions, consumed = cpp_input(parameter, argument_index)
        lines.extend("        " + line for line in emitted)
        call.extend(expressions)
        argument_index += 1
        index += consumed
    lines.extend("        " + line for line in locals_)
    lines.append(f"        const auto status = {operation['cSymbol']}({', '.join(call)});")
    for name, kind, _ in output_names:
        if kind == "buffer":
            lines.append(f"        BufferOwner owned_{name}({name});")
    lines.append("        check_native(env, status, error);")
    result = actual_result(operation)
    if result == "void":
        expression = "undefined(env)"
    elif result == "bytes":
        name = next(n for n, kind, _ in output_names if kind == "buffer")
        expression = f"buffer_result(env, owned_{name}.get())"
    elif result in {"uint32", "int32"}:
        name = next(n for n, kind, semantic in output_names
                    if kind in {"u32", "i32"} and semantic == "output")
        expression = f"number_result(env, {name})"
    elif result == "boolean":
        name = next(n for n, _, semantic in output_names if semantic == "boolean_output")
        expression = f"boolean_result(env, {name} != 0)"
    elif result == "authentication_info":
        name = next(n for n, kind, _ in output_names if kind == "authentication")
        expression = f"authentication_result(env, {name})"
    elif result == "delegated_application_info":
        name = next(n for n, kind, _ in output_names if kind == "delegated")
        expression = f"delegated_result(env, {name})"
    elif result in {"native_response", "iso_response"}:
        status_semantic = "native_status" if result == "native_response" else "iso_status"
        status_name = next(n for n, _, semantic in output_names if semantic == status_semantic)
        buffer_name = next(n for n, kind, _ in output_names if kind == "buffer")
        expression = f"status_response(env, {status_name}, owned_{buffer_name}.get())"
    else:
        raise ValueError(f"Unsupported result {result}")
    lines.extend([f"        return {expression};", "    }"])
    return lines


def declarations(operations: list[dict], surface: str, interface: str) -> list[str]:
    """Generate one strict TypeScript method interface."""
    lines = [f"export interface {interface} {{"]
    for operation in operations:
        if operation["surface"] != surface or operation["name"] in RUNTIME:
            continue
        signature: list[str] = []
        for arg in public_arguments(operation):
            optional = "?" if arg["kind"] == "timeout" else ""
            signature.append(f"{arg['name']}{optional}: {TS_TYPES[arg['kind']]}")
        if surface == "offline":
            signature.append("options?: Readonly<{ signal?: AbortSignal }>")
        lines.extend([
            f"    /** {operation['summary']} */",
            f"    {operation['name']}({', '.join(signature)}): Promise<{RESULT_TYPES[actual_result(operation)]}>;",
        ])
    lines.extend(["}", ""])
    return lines


def generate(check: bool = False) -> list[Path]:
    """Regenerate every deterministic Node binding inventory file."""
    package = Path(__file__).resolve().parents[1]
    root = package.parents[1]
    manifest = json.loads((root / "api/ev3-api.json").read_text())
    operations = manifest["operations"]
    stale: list[Path] = []

    def emit(path: Path, content: str) -> None:
        expected = content.encode()
        if check:
            if not path.exists() or path.read_bytes() != expected:
                stale.append(path.relative_to(root))
        else:
            path.write_bytes(expected)

    callable_ops = [operation for operation in operations if operation["name"] not in RUNTIME]
    metadata_items = {operation["name"]: metadata(operation) for operation in callable_ops}
    operation_source = (
        "/** Generated from api/ev3-api.json; contains no protocol encoding. */\n"
        f"export const MANIFEST_SHA256 = {json.dumps((root / 'api/ev3-api.sha256').read_text().strip())};\n"
        "export const operations = Object.freeze(" + json.dumps(metadata_items, indent=2) + ");\n"
        "export const managedOperations = Object.freeze(Object.fromEntries(\n"
        "    Object.entries(operations).filter(([, value]) => value.surface === 'managed')));\n"
        "export const rawOperations = Object.freeze(Object.fromEntries(\n"
        "    Object.entries(operations).filter(([, value]) => value.surface === 'raw')));\n"
        "export const offlineOperations = Object.freeze(Object.fromEntries(\n"
        "    Object.entries(operations).filter(([, value]) => value.surface === 'offline')));\n"
    )
    emit(package / "src/operations.mjs", operation_source)

    inventory_ts = [
        "/** Generated ABI operation inventory; do not edit. */",
        f"export const ABI_VERSION = {manifest['abiVersion']} as const;",
        f'export const MANIFEST_SHA256 = "{(root / "api/ev3-api.sha256").read_text().strip()}" as const;',
        "export const OPERATIONS = {",
    ]
    inventory_js = [
        "/** Generated ABI operation inventory; do not edit. */",
        f"export const ABI_VERSION = {manifest['abiVersion']};",
        f'export const MANIFEST_SHA256 = "{(root / "api/ev3-api.sha256").read_text().strip()}";',
        "export const OPERATIONS = Object.freeze({",
    ]
    for operation in operations:
        inventory_ts.append(
            f'  {operation["id"]}: {{ name: "{operation["name"]}", '
            f'symbol: "{operation["cSymbol"]}", surface: "{operation["surface"]}" }},')
        inventory_js.append(
            f'  {operation["id"]}: Object.freeze({{ name: "{operation["name"]}", '
            f'symbol: "{operation["cSymbol"]}", surface: "{operation["surface"]}" }}),')
    inventory_ts += ["} as const;", ""]
    inventory_js += ["});", ""]
    emit(package / "src/raw/operations.generated.ts", "\n".join(inventory_ts))
    emit(package / "src/raw/operations.generated.mjs", "\n".join(inventory_js))

    ts = [
        "/** Generated public operation contracts from api/ev3-api.json. */",
        "import type { KeySourceValue } from './keys.js';",
        "export type TimeoutArgument = number | Readonly<{ timeoutMs?: number; signal?: AbortSignal }>;",
        "export interface AuthenticationInfo { readonly transactionIdentifier: Uint8Array; readonly piccCapabilities: Uint8Array; readonly pcdCapabilities: Uint8Array; }",
        "export interface DelegatedApplicationInfo { readonly slotVersion: number; readonly quotaLimit: number; readonly freeBlocks: number; readonly applicationId: number; }",
        "export interface NativeResponse { readonly data: Uint8Array; readonly status: number; }",
        "export interface IsoResponse { readonly data: Uint8Array; readonly status: number; }",
        "export interface PiccConfiguration { readonly disableFormat?: boolean; readonly randomIdentifier?: boolean; readonly proximityCheckMandatory?: boolean; readonly virtualCardAuthenticationMandatory?: boolean; readonly errorCodeBinding?: boolean; readonly randomIdentifierConfiguration?: boolean; readonly fourByteNuidConfiguration?: boolean; }",
        "export interface TransactionOperation { readonly kind: number; readonly file: number; readonly communication: number; readonly offset?: number; readonly record?: number; readonly amount?: number; readonly data?: Uint8Array; }",
        "export interface NativeRequest { readonly framing: number; readonly command: number; readonly data?: Uint8Array; readonly maximumResponse: number; readonly firstFrameDataSize?: number; readonly flags?: number; }",
        "export interface NativeSecureRequest { readonly profile: number; readonly command: number; readonly header?: Uint8Array; readonly data?: Uint8Array; readonly requestCommunication: number; readonly responseCommunication: number; readonly minimumResponse?: number; readonly maximumResponse: number; readonly firstFrameDataSize?: number; readonly flags?: number; readonly invalidatesSession?: boolean; }",
        "export interface IsoApdu { readonly cla: number; readonly ins: number; readonly p1: number; readonly p2: number; readonly data?: Uint8Array; readonly le?: number; readonly lengthEncoding?: number; readonly correctLength?: boolean; readonly maximumResponse: number; readonly maximumFrames: number; }",
        "export interface DelegatedApplicationConfiguration { readonly applicationId: number; readonly keySettings: number; readonly numberOfKeys: number; readonly slot: number; readonly slotVersion: number; readonly quotaLimit: number; readonly isoFileIdentifiers?: boolean; readonly keySettings3?: number; readonly isoId?: number; readonly dfName?: Uint8Array; readonly activeKeySetVersion?: number; readonly numberOfKeySets?: number; readonly maximumKeySize?: number; readonly keySetSettings?: number; }",
        "",
    ]
    ts += declarations(operations, "managed", "ManagedOperations")
    ts += declarations(operations, "raw", "RawOperations")
    ts += declarations(operations, "offline", "OfflineOperations")
    emit(package / "src/operations.d.ts", "\n".join(ts))

    dispatch = [
        "/** @file dispatch.inc Generated C ABI calls; no card protocol encoding. */",
        "napi_value dispatch_managed(napi_env env, Context& context, const std::string& operation,",
        "                            napi_value arguments) {",
        "    df_error error{};",
    ]
    for operation in operations:
        if operation["surface"] == "managed" and operation["name"] not in PROVIDER_DIRECT:
            dispatch += cpp_operation(operation)
    dispatch += ["    throw BridgeFailure(\"Unknown managed C ABI operation\");", "}", "",
                 "napi_value dispatch_raw(napi_env env, Context& context, const std::string& operation,",
                 "                        napi_value arguments) {", "    df_error error{};"]
    for operation in operations:
        if (operation["surface"] == "raw" and operation["name"] not in RUNTIME and
                operation["name"] not in PROVIDER_DIRECT):
            dispatch += cpp_operation(operation)
    dispatch += ["    throw BridgeFailure(\"Unknown raw C ABI operation\");", "}", "",
                 "napi_value dispatch_offline(napi_env env, const std::string& operation,",
                 "                            napi_value arguments) {", "    df_error error{};"]
    for operation in operations:
        if operation["surface"] == "offline" and operation["name"] not in PROVIDER_DIRECT:
            dispatch += cpp_operation(operation)
    dispatch += ["    throw BridgeFailure(\"Unknown offline C ABI operation\");", "}", ""]
    emit(package / "native/dispatch.inc", "\n".join(dispatch))
    return stale


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail without writing when generated files differ")
    arguments = parser.parse_args()
    differences = generate(arguments.check)
    if differences:
        print("Generated Node binding files are stale:", file=sys.stderr)
        print("\n".join(str(path) for path in differences), file=sys.stderr)
        raise SystemExit(1)
