# Raw and managed APIs

Raw APIs are an expert escape hatch for complete transport access. They preserve opcode,
payload, framing, response status, delivery outcome, and configured continuation behavior.
They perform bounds and lifecycle validation but do not turn an unknown payload into a
supported typed feature.

Secure raw requests explicitly identify the bytes that remain clear, the bytes protected
as command data, the expected response protection, and the active session family. The SDK
does not guess those boundaries for arbitrary commands.

Managed APIs expose strong identifiers, named settings, parsed results, explicit
authentication variants, and bounded transaction plans. They enforce selection/session
transitions and reject unsupported layouts before transmission.

Managed and raw handles are opened separately and exclusively own their activated
transport. No raw escape method is exposed from a managed Card because an untracked raw
command can invalidate the Card's selected application, command counter, IV, or staged
transaction.
