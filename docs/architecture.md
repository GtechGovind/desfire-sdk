# EV3 architecture and structural standards

The active product is DESFire EV3. The archive/pre-ev3-compatibility branch preserves
other-generation work. Do not reintroduce other profiles into the EV3 API.

- `foundation/`: bytes, Result, errors, move-only secrets, transport and crypto contracts.
- `core/include/desfire/ev3/`: public typed EV3 contracts and independent protocol codecs.
- `core/src/`: managed card operations and protocol execution; private security under `security/`.
- `providers/crypto-openssl/`: vetted primitives; no OpenSSL declarations in core public headers.
- `transports/`: independently built callback, replay, and PC/SC adapters.
- `c-api/`: versioned C99 declarations, opaque handles, owned outputs, exception containment.
- `sdk/`: thin C++17, Python, Node/TypeScript, Kotlin/JNI, and Apple facades over the C ABI.
- `tests/`: independent wire fixtures, cryptographic vectors, scenario and binding tests.
- `spec/`: actual command coverage and qualification status.
- `docs/`: contracts, build, ownership, recovery, and hardware acceptance evidence.

The dependency direction is SDK facade -> C ABI -> core -> foundation. Transports and
crypto providers depend on foundation; the protocol core never imports a reader SDK,
JNI, Python, Node, or UI framework. Framing, ISO-DEP fragmentation, and DESFire AF
continuation are distinct layers. All protection and protocol behavior stays in C++.

One Card exclusively owns one activated transport. One lock spans every command and
all its continuation frames. Session families have separate state, and mode changes
must explicitly reset or select/authenticate. Unknown delivery is never retried.
API output allocation does not run a card operation twice. Cancellation bypasses the
operation lock. No production keys or vendor source are distributed.

The detailed design is split into:

- [core layers](architecture/core-layers.md);
- [native protocol framing](architecture/native-protocol.md);
- [raw and managed APIs](architecture/raw-and-managed-apis.md);
- [security profiles](architecture/security-profiles.md);
- [key resolution](architecture/key-resolution.md); and
- [transport lifecycle](architecture/transport-lifecycle.md).

Read the [coding standards](coding-standards.md) before editing. Every claimed feature requires
implementation, a typed API, independent success/failure tests, and explicit host versus card
evidence.
