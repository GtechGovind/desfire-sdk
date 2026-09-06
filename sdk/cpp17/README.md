# C++17 compatibility facade

Include `<desfire/cpp17.hpp>` and link the installed `desfire::cpp17` CMake target. The
target requires C++17 and links only the installed C ABI. It never exposes or includes the
modern C++23/C++26 core headers.

The primary `desfire::cpp17` API returns `Result<T>` and compiles with exceptions disabled.
Each `Error` owns the stable code, delivery outcome, card status, and redacted diagnostic from
one C call. Test a result before using `value()` or `error()`. The optional
`<desfire/cpp17/throwing.hpp>` header provides `throwing::value_or_throw` for applications that
choose exception-based control flow; it is intentionally absent from the primary umbrella.

`Card`, `raw::Card`, `raw::Channel`, `raw::Buffer`, and `Aes128Key` use RAII and have one owner.
`Card` adds strong application, file, key, key-set, ISO-file, offset, count, access-right, and
settings types plus `std::chrono::milliseconds`. The current ABI v1 baseline allowlists 125
exports; the raw handle classes and `offline` namespace cover all 120 fallible manifest operations, including all
21 offline direct/provider entries and all raw native, ISO, and secure exchanges.
`raw::Buffer::copy()` copies an owned C response without executing the card operation again.

Every open verifies C ABI version 1 and the generated manifest SHA-256 before creating a handle.
The 120-operation inventory and its current digest are installed with the facade, so a mismatched
runtime fails locally with `unsupported` and `not_sent` evidence.

AES operations accept a direct `Aes128Key`, a custom `Aes128KeyDeriver`, or a synchronous
`Aes128KeyProvider`. Derivers and providers return `Result<Aes128Key>` and are `noexcept` so the
same contract works in `-fno-exceptions` programs. Provider requests carry bounded non-secret
reference, diversification, routing, purpose, profile, scope, and cancellation metadata. Key
resolution completes once before the first card frame; provider failures retain a `not_sent`
outcome.

Offline typed helpers cover AN10922 AES-128 derivation, delegated EncK and authorization MACs,
MIFARE Classic license MAC, transaction session-key derivation, TMV calculation/verification,
ReaderID decryption, and originality-signature verification. These helpers do not communicate
with a card. The caller supplies complete authoritative TMI because automatic EV3 TMI construction
is unavailable. The caller still owns replay/counter policy and originality trust anchors.

One Card owns one activated transport. Its callbacks and externally managed context must remain
valid for the Card lifetime unless the C transport descriptor supplies paired retain/release
callbacks. Do not destroy a Card concurrently with an operation. `cancel()` bypasses the active
operation lock. Treat `Outcome::unknown` as a reconciliation boundary and never blindly retry a
mutation.

C++ versions older than C++17 use `<desfire.h>` directly.
