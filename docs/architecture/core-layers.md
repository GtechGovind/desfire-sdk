# Core layers

The installed core module has one protocol library target: `desfire::ev3_core`. Its public
headers expose model, native, ISO/IEC 7816, security, offline, and managed namespaces. Internal
build partitions are implementation details and never appear in the package export.

## Runtime dependency direction

Dependencies point toward lower layers. A lower layer never imports a managed card, reader SDK,
provider implementation, C ABI, or language binding.

| Layer | Owns | May depend on |
| --- | --- | --- |
| `foundation` | Bytes, results, errors, secret storage, transport and crypto interfaces | Standard library, threads |
| `model` | Range-checked identifiers, settings, communication modes, version parsing | `foundation` |
| `native::raw` | Native and wrapped framing, AF continuation, generation and deadline checks | `foundation` |
| `native::checked` | Documented native command layouts and complete response parsing | `model`, `foundation` |
| `security::key_derivation` | AES-128 key ownership, providers, and documented diversification | `model`, `foundation` |
| `security::{standard_aes,ev2}` | Authentication transcripts, session keys, counters, MAC and encryption state | `model`, `native::raw`, `foundation` |
| `native::secure` | Applying one verified native session to one checked request | `native::raw`, native security sessions |
| `iso7816::raw` | APDU encoding, response decoding, 61xx continuation, transport serialization | `foundation` |
| `iso7816::checked` | Documented ISO command variants and semantic response validation | `iso7816::raw`, `foundation` |
| `iso7816::security::aes` | ISO mutual AES authentication and verified ISO session protection | `iso7816::checked`, `foundation` |
| `offline` | Deterministic issuer MAC, license MAC, transaction MAC, and signature helpers | `model`, `native::checked`, `foundation` |
| `managed` | Selection, authentication-family state, operation serialization, recovery policy | Every preceding core layer |

`native::raw` accepts an opcode and bytes. It validates structural lengths, deadlines, transport
generation, and response framing, but does not claim that arbitrary bytes implement a documented
NXP command. `native::secure` authenticates and decrypts the complete response before returning
plaintext. A MAC, padding, counter, generation, or ambiguous-delivery failure invalidates the
session.

`native::checked` and `iso7816::checked` are the typed command boundary. A feature counts as
implemented only when this layer owns its validated layout and complete response parser. Missing
or uncertain layouts fail before transport I/O.

`managed::Card` owns one activated transport, selected application state, authentication state,
and one operation mutex. The lock covers the complete logical exchange, including key-provider
resolution, continuation frames, mutation staging, and commit. Cancellation bypasses that lock.

## Build ownership

`core/CMakeLists.txt` compiles each source domain as a private position-independent object target.
The partitions expose domain membership in the build graph while retaining translation-unit
incremental builds and parallel compilation across unrelated domains.

| Private target | Source ownership |
| --- | --- |
| `ev3_core_model_objects` | `core/src/model/**` |
| `ev3_core_native_raw_objects` | `core/src/native/raw/**` |
| `ev3_core_native_checked_objects` | `core/src/native/checked/**` |
| `ev3_core_key_derivation_objects` | `core/src/security/key_derivation/**` |
| `ev3_core_standard_aes_objects` | `core/src/security/standard_aes/**` |
| `ev3_core_ev2_objects` | `core/src/security/ev2/**` |
| `ev3_core_native_secure_objects` | `core/src/native/secure/**` |
| `ev3_core_iso7816_raw_objects` | `core/src/iso7816/raw/**` |
| `ev3_core_iso7816_checked_objects` | `core/src/iso7816/checked/**` |
| `ev3_core_iso7816_aes_objects` | `core/src/iso7816/security/aes/**` |
| `ev3_core_offline_objects` | `core/src/offline/**` |
| `ev3_core_managed_objects` | `core/src/managed/**` |

`ev3_core_build_interface` supplies only the source-tree include path and `foundation` usage
requirements to those object targets. `ev3_core` composes every object exactly once into a static,
PIC-safe archive and publicly links `foundation`. Neither the build interface nor any object target
is installed. The package exports only `desfire::ev3_core` for the modern protocol implementation.

Every object target receives the same warning, language, visibility, and sanitizer compile policy.
The final core target receives sanitizer link requirements. This instruments the code that is
actually archived and preserves sanitizer runtime flags when a test or shared C ABI links it.

## Language and package boundary

C++26 is the default source mode. Configuration probes the compiler's exact C++26 flag and fails
instead of downgrading when an older CMake release lacks feature metadata. The
`core-only-compat23` preset builds and tests the same source set under C++23.

The selected implementation language remains private in installed library targets. A modern core
consumer explicitly compiles its translation units as C++23 or C++26. The C ABI exposes C99 only,
and the C++17 facade includes and links that C ABI; neither inherits a C++26 requirement through a
private implementation link. `tests/install-consumer` verifies the canonical modern headers and
symbols from an installed package without using removed flat headers.

## Transport ownership

One activated transport belongs to exactly one `managed::Card` or one independently managed raw
channel. Sharing it with another protocol engine can change selection, counters, IVs, transaction
state, or transport generation without either owner observing a coherent transition.
