# EV3 implementation and qualification matrix

This file distinguishes implemented software paths from target qualification. A command is
listed as implemented only when it has a checked encoder/parser or managed operation and an
independent success/failure fixture. Replay evidence verifies deterministic bytes and state; it
does not prove behavior on an RF link or a provisioned EV3 card.

Binding rows describe the implemented verification surface. The evidence column names checks that
must pass for a qualified source revision; it does not claim they ran against the current working
tree. The canonical manifest and each binding's conformance test decide parity; copied raw bytes
alone do not count as typed support. Current results are recorded only in
`qualification-record.yaml`.

| Area | Implemented behavior | Evidence | Current boundary |
| --- | --- | --- | --- |
| Native framing | Direct native frames and proprietary `90 INS` ISO-wrapped frames | Exact byte fixtures in `ev3_native_raw_test`; native/wrapped long-transfer scenarios | Reader-specific activation and RF fragmentation belong to the adapter |
| Native continuation | Bounded command upload and response AF assembly under one deadline/lock | Boundary failures and transfers through 65,536 bytes in `ev3_long_exchange_test` | Declared reader and card frame limits remain authoritative |
| Discovery/selection | GetVersion, FreeMem, application IDs, unauthenticated DF names, ISO file IDs, native file IDs, application selection | Command/parser tests and managed Card tests, including pre-I/O rejection of GetDFNames during AES/ISO authentication | GetVersion bytes are preserved; generation is not guessed from one response |
| Native AES security | Standard AES authentication (`0xAA`), EV2 AES First with zero-through-six-byte PCD capabilities, EV2 AES NonFirst, AES key changes, AN10922 AES diversification | Published authentication and key-change vectors; exact capability request/echo, counter/IV continuity, tamper/padding/provider failures in `ev3_standard_aes_test`, `ev3_security_test`, and `ev3_card_test` | Native DES/2K3DES/3K3DES authentication is not implemented |
| Native secure messaging | Standard-AES chained-IV and EV2 counter-based Plain, MAC, and Full request/response processing with private session keys | Published Standard-AES read/write vectors, multi-frame EV2 encrypted reads, integrity rejection, counter exhaustion, and sanitizers | File policy and provisioned keys must match the target card |
| Applications/keys | Create/delete application, delegated create/query/delete, key settings/version, AES key changes, initialize/finalize/roll key set; offline AES EncK and create/delete/delegated-configuration DAM MAC generation | Exact command/chaining fixtures, public AN12696 create known answers, independently authored synthetic configuration fixtures, independent OpenSSL delete/configuration MAC answers, authenticated Card workflows, and preflight range failures; no nonpublic vector is embedded | No authoritative option-6 SetConfiguration card-payload layout is recorded |
| Files | Standard/backup data, value, linear/cyclic record, transaction-MAC file creation; settings, delete, read/write/update/clear and value operations | Exact encodings, malformed parser fixtures, C access-rights regression | SDM layout and SDM provisioning are unimplemented |
| MIFARE Classic compatibility | RestoreTransfer between two value files using Plain or MAC communication; offline AES MFCLicenseMAC over an explicit structurally checked license and caller-supplied sector secrets | Exact target/source command data and Standard-AES CMAC-chain fixtures; independent OpenSSL license-MAC answer; boundary/provider/exception failures | No authoritative option-dependent typed layouts are recorded for CreateMFCMapping or RestrictMFCUpdate; sector-secret subfields remain caller-owned |
| Transactions | Credit/debit/limited credit, explicit commit/abort, ReaderID commit, optional transaction-MAC receipt; bounded managed batch | Lost-commit uncertainty and transactional file-type/policy scenarios | Caller begins with the intended staged state; no mutation is retried after uncertain delivery |
| Card management | UID with omitted/without-NUID/with-NUID request variants, originality-signature read and explicit-key offline verification, format, local authentication reset, selected PICC/capability/default-key/ATS/ATQA configuration | Exact option-byte and encrypted-response fixtures, strict UID/NUID parsing, managed-state fixtures, and a genuine shared-construction signature vector for offline verification | SAK and virtual-card identifier configuration are fail-closed; EV3 authoritative layouts are unavailable |
| Transaction-MAC offline tools | AES transaction-key derivation, TMV calculation/verification, encrypted ReaderID decryption | Known-answer/boundary/tamper tests in `ev3_offline_test` | Caller supplies complete authoritative TMI; automatic EV3 TMI construction is unimplemented |
| Actual ISO 7816 | Select FID/DF name, read/update binary, read/append/update records (both `DC` and `DD`), challenge, external/internal authentication APDUs, short/extended lengths, bounded `61xx`, safe read-only `6Cxx` correction | Exact APDU, continuation, malformed, exception and session-state tests in `ev3_iso7816_test` | Primitive external/internal authentication accepts caller-prepared data; it does not establish managed trust |
| ISO AES session | Complete mutual AES authentication and retained-IV response CMAC for authenticated reads | Native/OpenSSL and independent Kotlin/JCE host fixtures | ISO writes use card-defined plain commands; managed ISO TDEA authentication is not implemented |
| C ABI v1 | 125 allowlisted exports, versioned C99 headers, opaque non-reused handles, per-call errors/outcomes, owned buffers, callback transport | C99 runtime, C11 layout/offset baseline, every public C header compiled alone, stale-handle, reentry, provider and allocation-before-I/O fixtures | The callback transport is the C reader integration point; no C PC/SC enumeration API |
| C++17 | RAII typed facade over `desfire::c`, installed as `desfire::cpp17`, with all 120 fallible manifest operations and 21 offline entries | Strict C++17 normal, `-fno-exceptions`, throwing, installed-consumer, standalone-header, provider and known-answer tests | Its implementation remains the C++23/C++26 native library behind ABI v1 |
| Python | Typed Python 3.10+ sync/async `ctypes` facade with managed, expert raw and all offline operations | 28 tests on Python 3.10 and 3.14, strict mypy, Ruff, generated parity, clean wheel install and known-answer smoke test | Native library is supplied separately; other Python runtimes are not recorded |
| Node/TypeScript | Typed N-API facade with managed, expert raw and offline workers plus asynchronous reader/provider rendezvous | 20 native integration tests on Node 20, 22, 24, and 26 on Linux; strict TypeScript, generated parity and package verification | macOS and Windows addon execution remain unrecorded |
| Kotlin/JVM | Suspend-first and blocking APIs with managed, expert raw, all offline operations and key providers over JNI | C++23/C++26 JNI host conformance, cancellation/reentry, JCE crypto fixtures, generated parity and compiled example | JNI shared-library deployment remains platform-specific |
| Android | IsoDep adapter and AAR packaging for ARM64, ARMv7 and x86_64 JNI/C/C++ runtimes | Current commit evidence: all three ABI cross-build/export/dependency checks, 16 KiB ARM64/x86_64 ELF alignment, release lint, Android-test/example compilation, AAR hashes, APK native/hash/ZIP-alignment verification, and SDK/JNI plus showcase instrumentation on an API 37.0 16 KiB emulator | Physical-NFC execution, API 23 runtime, and ARMv7 device execution remain unqualified |
| Swift | Swift 6 package with managed, expert raw, all offline operations, key providers and separate CoreNFC product | 14 macOS tests with strict concurrency/warnings-as-errors, manifest parity, macOS 14 native build, and iOS 16 device/simulator source builds | No assembled signed XCFramework, physical CoreNFC exchange or physical-card evidence |

## Explicitly unavailable operations

The following return `unsupported` before transmission or have no public operation. They must not
be represented as working EV3 support:

- SDM conditional settings parsing, SDM provisioning, URL/file mirroring, and SDM verification.
- Automatic EV3 transaction-MAC input accumulation. Offline TMV APIs require caller-supplied TMI.
- SAK and virtual-card identifier `SetConfiguration` payloads.
- Delegated option-6 `SetConfiguration` card payload construction.
- Proximity-check, virtual-card selection, and card-emulation workflows.
- AuthenticatePDC; no authoritative public response layout and independent EV3 vectors are
  recorded.
- MIFARE Classic mapping and update-restriction card commands; no authoritative option-dependent
  typed layouts are recorded.
- Managed native DES/2K3DES/3K3DES authentication and managed ISO 2K3DES/3K3DES authentication.
- SAM/HSM implementations, production key injection, certification scripts, and reader firmware.

The NXP Reader Library `SetConfig`, `GetConfig`, and `SetVCAParams` entries configure that
library's host-side data structures; they are not additional DESFire card commands. Equivalent
reader and policy configuration belongs to this SDK's transport or integrating application.

Adding a missing operation requires an authoritative field layout, typed API, exact independent
wire fixtures, malformed/failure coverage, binding generation, and target evidence. Expert raw
channels are explicit, separately owned, bounded, and do not turn an unknown opcode into typed
support.
