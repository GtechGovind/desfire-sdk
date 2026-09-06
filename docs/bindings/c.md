# C ABI

The C99 ABI is the compatibility boundary for C, older C++, and foreign-language
bindings. Include `<desfire.h>` for the whole surface or individual `<desfire/...>`
headers for narrower dependencies.

The current ABI v1 baseline allowlists 125 symbols and maps all 120 fallible operations in the
canonical manifest. Follow the [C package guide](../../c-api/README.md) for a source build,
installed CMake target, offline example, and reader integration links.

Each call returns its own status and optional `df_error`. Handles are opaque, monotonic,
and never reused. Inputs are borrowed only until return. Owned output objects must be freed
exactly once with their matching function. No C++ type, exception, allocator object, or
thread-local last-error state crosses the ABI.

Transport and key-provider descriptors use `struct_size`, `abi_version`, context, and
paired retain/release callbacks. Closing waits for in-flight callback leases; a busy close
leaves the handle and callback ownership intact.

Direct-key and provider authentication functions are distinct for Standard AES, EV2 First,
EV2 NonFirst, and ISO AES. Provider failures happen before card I/O and report `not_sent`.
Offline transaction-MAC calculation and verification require the caller's complete authoritative
TMI; automatic EV3 TMI construction is unavailable.

The raw-channel handle is independent of a managed Card. It preserves exact native or ISO
status and delivery outcome. Do not let another engine use the activated reader while either
handle owns it.
