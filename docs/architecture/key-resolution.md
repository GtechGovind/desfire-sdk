# Key resolution and derivation

Operations accept an already-derived AES-128 key, a master key plus a derivation strategy,
or a provider request containing a non-secret reference and caller context. This lets an
application retain its own diversification policy without placing that policy in the SDK.

A provider resolves each required key exactly once while the card operation owns its FIFO
slot and before the first card frame. Authentication and key-change operations validate all
returned keys as exactly sixteen bytes before transmission. A provider failure, invalid
length, or cancellation therefore reports `not_sent`.

The built-in `nxp_aes128` implementation provides the documented NXP AES-128
diversification construction. It never infers a UID, application ID, system identifier,
or byte order; those bytes belong to the caller's derivation context.

Provider callbacks write into SDK-owned storage and may not return or retain pointers.
Temporary SDK copies are wiped on all exits. References, context bytes, master keys,
derived keys, session keys, and cryptograms are excluded from logs and diagnostics.

This interface supports software or remote providers that return exportable AES key bytes.
An opaque SAM/HSM key requires a separate primitive contract for CBC, CMAC, random-number,
and session-key operations and is not represented as a byte-returning provider.
