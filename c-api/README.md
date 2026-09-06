# DESFire EV3 C API

The C API is the versioned ABI boundary for C99/C11 applications, older C++ toolchains, and the
managed language bindings in this repository. It exposes managed operations, expert raw exchange,
offline AES utilities, callback transports, and custom exportable-key providers without placing C++
types or exceptions in public headers.

## Build and install

From the repository root:

```sh
cmake -S . -B build/c-api -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DDESFIRE_CXX_STANDARD=23 \
  -DDESFIRE_BUILD_C_API=ON \
  -DDESFIRE_BUILD_PCSC=OFF
cmake --build build/c-api --parallel
cmake --install build/c-api --prefix "$PWD/build/install"
```

Consume the installed target:

```cmake
find_package(desfire-sdk CONFIG REQUIRED)

add_executable(reader main.c)
set_target_properties(reader PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
target_link_libraries(reader PRIVATE desfire::c)
```

Include `<desfire.h>` for the complete surface or one of the self-contained
`<desfire/*.h>` headers for a narrower dependency.

## ABI contract

- ABI version 1 currently allowlists 125 exported symbols.
- Every versioned descriptor begins with `struct_size` and `abi_version`; callers zero reserved
  fields so later libraries can extend the structure safely.
- Handles are opaque and monotonic. A stale numeric handle never aliases a newly opened object.
- Inputs are borrowed only for the call. Owned buffers and result objects are immutable and must be
  released once with their matching function.
- Every fallible call returns its own `df_error`; there is no thread-local last error.
- C++ exceptions and allocator objects never cross the ABI boundary.
- Direct-key and provider-key entry points are separate, and provider failures occur before card
  I/O with a `DF_NOT_SENT` outcome.

The exact baseline is recorded in [`abi/abi-v1.symbols`](abi/abi-v1.symbols) and checked against ELF,
Mach-O, and PE export allowlists. The canonical operation mapping lives in
[`api/ev3-api.json`](../api/ev3-api.json).

## Reader ownership

`df_transport_v1` adapts an application-owned, already activated reader. Its exchange callback
sends one physical frame exactly once and returns exact bytes or structured failure evidence.
Optional retain/release hooks must be supplied as a pair. Close waits for admitted work and active
callback leases; if close fails, the handle remains recoverable.

A managed `df_card` and a `df_raw_channel` are separate owners and must not use the same active
reader connection concurrently. See [reader integration](../docs/reader-integration.md) and
[transport lifecycle](../docs/architecture/transport-lifecycle.md) before implementing callbacks.

## Errors and transaction recovery

`df_error` preserves the SDK error code, redacted diagnostic, device status, and delivery outcome.
Treat `DF_UNKNOWN` as a reconciliation boundary: the card may have applied a mutation, so
the application must not retry it blindly.

| Outcome | Meaning |
| --- | --- |
| `DF_NOT_SENT` | No card frame was transmitted |
| `DF_REJECTED` | The card returned a definite failure |
| `DF_SUCCEEDED` | Completion was confirmed |
| `DF_UNKNOWN` | Delivery or mutation completion cannot be established |

## Try the offline example

The repository's [C example](../examples/c/offline_key_derivation.c) executes NXP AES-128
diversification without a reader:

```sh
cmake --build build/c-api --target desfire_c_offline_example
./build/c-api/examples/desfire_c_offline_example
```

The [C binding contract](../docs/bindings/c.md) covers ownership and provider rules. The
[implementation matrix](../spec/coverage.md) records the supported surface and current
qualification limits.
