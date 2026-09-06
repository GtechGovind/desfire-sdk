# Native and ISO protocol boundaries

Native direct framing sends `command || data` and receives `status || data`. Native
ISO-wrapped framing sends proprietary `90 INS ...` APDUs and receives `data || 91 status`.
True ISO 7816 commands use CLA `00`, their own command layouts, and normal two-byte status
words. The three forms are separate API paths even when they use the same reader.

Reader or NFC-stack ISO-DEP fragmentation is outside the protocol core. DESFire `AF`
continuation and ISO `61xx` response assembly are core responsibilities. One deadline and
one transport generation apply to the entire logical operation.

The core never retries a frame after uncertain delivery. A transport must report whether
the frame was definitely not sent, rejected with a response, completed, or may have been
delivered. Once delivery is unknown, mutations require application-level reconciliation.

Raw ISO results preserve response data and status words, including warnings. Checked ISO
operations decide which status values satisfy their documented contract; they do not erase
valid warning payloads while constructing an error.
