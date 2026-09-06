# C++17 facade

Include `<desfire/cpp17.hpp>` and link `desfire::cpp17`. The facade is compiled by consumers
with exactly C++17 and depends only on the installed C ABI. Modern core headers are never
included through this target.

The primary API returns `desfire::cpp17::Result<T>`, including exact error, delivery outcome,
and device status. It supports `-fno-exceptions`; a separate throwing adapter is an opt-in
convenience. Card, raw handles, output buffers, transports, and scoped keys use RAII and are
move-only where ownership would otherwise be ambiguous.

Friendly operations use strong identifiers, named configuration types, `std::optional`, and
`std::chrono::milliseconds`. The current ABI v1 baseline allowlists 125 exports; the raw handle
classes plus the
offline namespace cover all 120 fallible manifest operations without implementing card framing
or cryptography.
Card/channel open verifies ABI version 1 and the generated manifest digest before allocating a
native handle. The 21 offline entries have typed direct/provider helpers for delegated
application, MIFARE Classic license, transaction-MAC/ReaderID, AN10922, and originality workflows.
Transaction-MAC calculation and verification require the caller's complete authoritative TMI;
the SDK does not construct EV3 TMI automatically.

Applications may pass an already-derived key, a custom `Aes128KeyDeriver`, or an
`Aes128KeyProvider`. C++ versions older than C++17 use `<desfire.h>` directly.
