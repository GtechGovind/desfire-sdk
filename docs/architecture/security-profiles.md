# AES security profiles

Standard AES authentication is native command `0xAA` and uses chained-IV AES secure
messaging. Its public name is `standard_aes`; `legacy` is not used for the command,
session, files, or APIs.

EV2 First creates a transaction identifier, command counter, and EV2 session keys. The
capability variant accepts zero through six PCD capability bytes and verifies the card's
returned capability data before installing the session. EV2 NonFirst requires an existing
verified EV2 context, replaces the session keys, and preserves the transaction identifier
and counter required by the documented protocol.

ISO mutual AES has an independent session and chaining state. ISO selection rules decide
when it survives or is discarded. ISO and native sessions cannot be substituted for one
another.

Protected plaintext is released only after response authentication, padding, length, and
counter checks succeed. Any integrity failure invalidates the affected session. Secret
buffers are move-only and wiped before releasing owned storage, with the documented limit
that the compiler, operating system, language runtime, or crypto provider may retain copies.
