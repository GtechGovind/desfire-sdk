# DESFire EV3 Python SDK

Python 3.10 and later use the versioned C99 ABI v1 through standard-library `ctypes`. The C++
core owns
all protocol encoding, secure messaging, and cryptography. The package checks ABI version 1 and the
canonical operation-manifest SHA-256 before opening a card or running an offline operation.

From the repository root, build `desfire::c` and install the Python package:

```sh
cmake -S . -B build/python-native -G Ninja \
  -DDESFIRE_BUILD_C_API=ON \
  -DDESFIRE_BUILD_OPENSSL=ON \
  -DDESFIRE_BUILD_PCSC=OFF
cmake --build build/python-native --target desfire_c --parallel
python -m pip install ./sdk/python
```

The library path is explicit. Use `libdesfire_c.dylib` on macOS, `libdesfire_c.so` on Linux, or
`desfire_c.dll` on Windows.

## Friendly synchronous and asynchronous cards

```python
from desfire_ev3 import (
    Aes128Key,
    ApplicationId,
    AsyncCard,
    AuthenticationProfile,
    Card,
    DerivationContext,
    Direct,
    Framing,
    KeyNumber,
    KeyPurpose,
    KeyRequest,
    Provider,
    TransportOptions,
)


class Reader:
    def exchange(self, request: bytes, timeout_ms: int) -> bytes:
        return device.transceive(request, timeout_ms)

    def reset(self) -> None:
        device.reset()

    def cancel(self) -> None:
        device.cancel()


native_library = "/absolute/path/to/libdesfire_c.dylib"
key = Aes128Key(application_key)
try:
    with Card(
        native_library,
        Reader(),
        TransportOptions(framing=Framing.ISO_WRAPPED),
    ) as card:
        card.select(ApplicationId(0x123456))
        card.authenticate_standard_aes(KeyNumber(0), Direct(key))
        version_payload = card.get_version()
finally:
    key.close()
```

`Card` serializes admitted logical operations in FIFO order. Provider and custom-deriver callbacks
run inside that queue before the first frame. Different cards can run concurrently. A callback that
reenters the same card receives `BUSY`. Close rejects new work, drains admitted work, and releases
native and callback ownership once. A failed close leaves the synchronous card recoverable.

`AsyncCard` owns one dedicated worker thread per card. Cancelling queued work raises `DesfireError`
with `Outcome.NOT_SENT` and performs no reader I/O. Cancelling active work calls the reader's
cancel path and waits for it to quiesce, retaining the reader/core delivery evidence. It never moves
a timed-out reader directly into another operation.

```python
async_key = Aes128Key(application_key)
try:
    async with await AsyncCard.connect(native_library, Reader()) as card:
        await card.select(ApplicationId(0x123456))
        metadata = await card.authenticate_ev2_first_aes_with_capabilities(
            KeyNumber(0),
            Direct(async_key),
            b"\x01\x02",
        )
finally:
    async_key.close()
```

## Keys

Authentication and key-changing workflows accept:

- `Direct(Aes128Key(...))` for an already-derived key.
- `Derived(master_key, context, deriver)` for application-defined derivation.
- `Provider(request, provider)` for non-secret key references.
- `AsyncProvider(request, provider)` on `AsyncCard` for a suspending key service.

Resolvers return an exportable 16-byte `Aes128Key`. Async providers execute on their event loop
while the dedicated card worker retains FIFO admission. They run exactly once before card I/O. Callback
messages are redacted on failure. Native and binding-owned temporary copies are overwritten on every
exit path. `Aes128Key.close()` overwrites its Python `bytearray`, though Python, extension modules,
or the operating system may retain copies outside that object's control. Key material, references,
and diversification context are never included in SDK diagnostics.

```python
class TenantKeys:
    def resolve(self, request: KeyRequest) -> Aes128Key:
        return vault.resolve_exportable_aes128(request.reference, request.context)


context = DerivationContext(
    purpose=KeyPurpose.AUTHENTICATION,
    key_number=KeyNumber(2),
    application=ApplicationId(0x123456),
    diversification_input=card_uid,
)
source = Provider(
    KeyRequest(
        reference=b"tenant/application/key-2",
        context=context,
        profile=AuthenticationProfile.EV2_FIRST,
    ),
    TenantKeys(),
)
with Card(native_library, Reader()) as provider_card:
    provider_card.select(ApplicationId(0x123456))
    provider_card.authenticate_ev2_first_aes(KeyNumber(2), source)
```

`Offline` exposes native AN10922 AES diversification, delegated-application authorization,
MIFARE Classic license MAC, transaction-MAC key derivation/calculation/verification, ReaderID
decryption, and originality verification. Every keyed workflow has a direct method and a `*_from`
method for `Direct`, `Derived`, or `Provider` resolution.
Transaction-MAC calculation and verification require complete authoritative TMI from the caller;
automatic EV3 TMI construction is unavailable.

## Expert raw channel

```python
from desfire_ev3.raw import IsoApdu, NativeRequest, RawCard

with RawCard(native_library, reader) as raw:
    native = raw.native_exchange(NativeRequest(command=0x60))
    iso = raw.iso_exchange(IsoApdu(0x00, 0xCA, 0x00, 0x00, le=256))
    print(native.status, native.data, iso.status_word, iso.data)
```

`RawCard` supports single-frame native, logical native with explicit continuation policy, direct or
ISO-wrapped native framing, true ISO APDUs with short/extended selection, Standard AES, EV2 First,
EV2 NonFirst, ISO AES raw sessions, checked ISO secure exchange, and explicit secure-native layouts.
It preserves native status bytes and ISO status words, including warning data. It never infers an
unknown command's secure header/data policy. One reader instance cannot back a managed and raw card
at the same time.

## Errors and recovery

Every native failure raises `DesfireError` with its stable `ErrorCode`, redacted message,
`Outcome`, and exact native or ISO status when available. `requires_reconciliation` is true for an
unknown delivery outcome. The SDK never retries a mutation after transmission. The application must
reconcile card state, then reset/reselect/reauthenticate as its workflow requires. Reader callbacks
must not reconnect or retry ambiguous exchanges internally.

## Generation and validation

```sh
python3 sdk/python/tools/generate_operations.py --check
DESFIRE_LIBRARY=/absolute/path/to/libdesfire_c.dylib PYTHONPATH=sdk/python/src \
  python -m unittest discover -s sdk/python/tests -v
python -m mypy --strict sdk/python/src/desfire_ev3
python -m build --outdir build/python-dist sdk/python
```

The generator reads all split C headers, proves their exports match `api/ev3-api.json`, and emits
the complete 120-operation Python raw inventory plus direct managed dispatch. Generated code never
contains APDU encoding or cryptography.

These tests provide host/replay and native known-answer evidence. They do not qualify physical EV3
cards, reader firmware and RF timing, SAM/HSM integration, mobile NFC transports, production keys,
or a deployment's transaction-recovery process.
