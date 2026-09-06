# Ownership, framing, and recovery

`c-api/include/desfire.h` is the authoritative ABI contract. ABI version 1 uses fixed-width
error fields, an opaque monotonic 64-bit card handle, and owned immutable output buffers.
No C++ type, exception, or thread-local last-error state crosses this boundary. Each
call returns its own error code, delivery outcome, device status, and redacted message.

## Activated transport ownership

The caller activates and selects a card, then supplies an exchange callback and explicit
frame limits to `df_open`. Callbacks receive one physical reader exchange and its remaining
timeout. The transport context must remain alive until close succeeds and every concurrent
call, including cancellation, has finished. The SDK retains callback metadata, not ownership
of the physical reader. `df_close` does not reset a card or abort a transaction.

Report external reset, removal, or reconnection using `df_notify_state_change`. Managed
operations check the transport generation before and after I/O. Do not share the activated
connection with another protocol engine while a Card owns it.

- `DF_NATIVE`: transmit native command bytes; responses begin with the native status byte.
- `DF_ISO_WRAPPED`: transmit native commands in proprietary `90 INS ...` APDUs; responses
  end in `91xx`. Actual ISO commands use their separate typed `00 INS ...` API and normal
  ISO status words on an APDU-capable transport.
- ISO-DEP/RF fragmentation belongs to the reader. DESFire additional-frame continuation
  and ISO `61xx` response handling belong to the protocol core.

A reader callback must return exact delivery evidence when an exchange fails. Exceptions
or unavailable evidence become unknown delivery. Do not hide a reconnect, card retry, or
partial exchange inside a callback. Honor cancellation and stop physical I/O before allowing
another exchange to start.

## Sessions and concurrency

Native AES First establishes private session keys, transaction identifier and command
counter. NonFirst preserves the verified transaction identifier and counter while replacing
keys. Every protected response is authenticated before plaintext is released. A failed MAC,
invalid padding, lost frame, generation change, or unusable secure state prevents continued
operations until a confirmed reset or a new connection.

ISO mutual AES owns a separate session and chaining IV. It is not interchangeable with
native EV2 secure messaging. DF selection resets authentication; EF selection may retain
an ISO session. Raw ISO authentication commands expose a frame API, while
`authenticate_iso_aes` performs and verifies the complete handshake.

One managed native C++ operation holds the connection lock through all continuation frames.
Same-thread callback reentry returns Busy. The C ABI also returns Busy for competing
operations. Cancellation bypasses that operation lock. Binding-specific queuing is described
in each SDK README; it does not permit interleaved physical exchanges.

## Outputs and transaction uncertainty

Pass a null `df_buffer*` slot to each buffer-returning call. Output ownership is allocated
before card I/O, and the bytes are available through `df_buffer_data`/`df_buffer_size`.
Free each successful buffer exactly once using `df_buffer_free`; do not reuse a freed pointer.
Buffer inspection is not a second card command. Scalar output addresses must be non-null.

Delivery outcomes are `not_sent`, `succeeded`, `rejected`, or `unknown`. A successful
transport call does not by itself establish a successful card operation: framing, status,
response shape, MAC, and padding still need validation. A lost commit response is unknown
and never retried automatically. Application recovery must use its own durable business
record and authenticated card state; reset alone does not prove that a debit did not happen.

Basic mutations and commit/abort are explicit in every binding. The modern C++
`execute_transaction` convenience method holds one lock/deadline across settings validation,
up to 128 backup/value/record mutations, and commit. It excludes standard files, validates
file type and protection before any mutation, and invalidates the session on an uncertain
staged transaction. Begin the batch without earlier staged changes unless those changes intentionally belong
in the same commit; the final commit also applies prior explicit staged mutations. That
batch method is not yet exposed through the C ABI.

## Packed C access rights

The C integer is a little-endian representation of the two native wire bytes. Its nibbles
from highest to lowest are **read, write, read/write, change**. For example, `0x1234`
means read key 1, write key 2, read/write key 3, and change key 4, transmitting bytes
`34 12`. Each selector is key 0..13, free access 14, or denied 15. Use the modern C++
`AccessRights` named fields when a packed value is unnecessary.

## Keys and limits

AES authentication accepts sixteen caller-supplied key bytes. The C++ diversification
provider supports host-defined derivation and the shared AN10922 AES construction. There
are no built-in master keys or guessed EV3 manufacturer verification keys. Managed C++
secret buffers erase their retained storage on destruction. Foreign-language callers own
and must manage their original byte arrays; operating systems and runtimes can retain copies.

Native logical responses are bounded to 16 MiB and continuation loops to 4096 physical
frames; actual transfer capacity also depends on the reader's declared native-frame size.
ISO exchange has separate configured response and continuation bounds. A maximum buffer
size is an allocation guard, not a claim that every card supports a transfer of that size.
