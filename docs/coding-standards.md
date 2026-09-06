# Engineering standards

The SDK uses C++26 (C++23 compatibility build; C99 ABI and C++17 facade for consumers) and explicit ownership. Protocol code is independently authored;
vendor source and restricted reference documents are never shipped with the SDK.

## Public contracts

- Document purpose, parameter units and valid ranges, ownership, thread safety,
  cancellation, and observable state changes. Explain recovery after ambiguous I/O.
- Return `Result<T>` for expected failures. Mark result types `[[nodiscard]]`.
  Exceptions and standard-library types must never cross the C ABI.
- Use distinct types for identifiers. Use tagged settings instead of untyped option
  integers. Accept binary data as byte spans, not hexadecimal text.
- Keep public headers self-contained. Keep implementation details and OpenSSL types
  out of installed headers.
- State capability limitations explicitly. An unavailable feature must return an
  error before transmission; a raw exchange is not a typed implementation.

## Implementation

- Follow `.clang-format`; use four spaces, indented namespace contents, and a 100-column
  limit. Separate functions and logical steps with blank lines. Prefer descriptive
  names, small functions, early validation, and explicit conversions at wire boundaries.
- Follow the byte-utilities implementation as the presentation reference: block-style
  Doxygen documentation with a summary, behavior, parameters, result, and relevant
  examples or notes. Explain the reason for important decisions inside the function.
- Prefer explicit `if`/`else` branches over dense conditional expressions in protocol
  and bit-manipulation code. Name constants and intermediate values by their purpose.
- Examples establish presentation, not protocol truth. Preserve verified wire behavior;
  document returned errors as returns, and reserve `@throws` for actual exceptions.
- Use RAII, move-only secret storage, and dependency injection. Avoid owning raw
  pointers, global sessions, implicit transport selection, and hidden reconnections.
- Explain protocol invariants and non-obvious decisions in comments. Avoid comments
  that merely repeat the next statement.
- Bound untrusted lengths before allocation or indexing. Check arithmetic before
  narrowing. Parse responses completely before reporting success.
- Serialize an entire logical exchange, including additional frames. Never retry
  mutations after uncertain delivery. Cancellation must not need the operation lock.
- Do not log secrets. Best-effort memory wiping cannot guarantee removal of copies
  made by the operating system, compiler, or cryptographic provider.

## Evidence and review

Tests must establish observable behavior using independent expectations: exact wire
frames, known-answer vectors, malformed responses, state transitions, and failure
outcomes. Tests that reproduce implementation logic do not establish correctness.

Keep formatting checks, compiler warnings, sanitizers, and API installation checks
repeatable. Record host tests separately from physical-card and SAM validation.
Document unfinished features rather than presenting placeholder files as support.

## Documentation

Every authored function must have a Doxygen documentation block at its declaration.
Every out-of-line definition must also have `@copydoc` or a complete Doxygen block.
This includes private helpers, constructors, destructors, operators, overrides,
callbacks, and test functions. Reuse the public declaration with `@copydoc` instead of
copying prose that could drift. Explain purpose and relevant inputs, outputs, ownership,
state changes, and failure behavior. Implementation comments should explain why
non-obvious steps are needed.

Use Doxygen `@brief`, `@param`, `@return`, `@pre`, and `@warning` when they add useful
contract information. Examples must compile against the published API. Each supported
operation needs a coverage entry linking its implementation and tests; hardware claims
also need a dated device/firmware evidence record.

Use `/** ... */` blocks for API comments so CLion can render them as documentation.
Document each overload's reference lifetime and failure behavior separately. Keep blank
lines between members and around access specifiers; do not introduce `explicit` or other
semantic changes while formatting. See [CLion documentation setup](clion-documentation.md).
