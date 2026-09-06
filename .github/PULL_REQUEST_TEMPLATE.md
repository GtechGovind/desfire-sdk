## Problem and resulting behavior

Describe the concrete trigger, previous behavior, and behavior after this change.

## Affected surfaces

- [ ] Modern C++ core
- [ ] C ABI or ABI baseline
- [ ] C++17 facade
- [ ] Kotlin/JVM or Android
- [ ] Python
- [ ] Node/TypeScript
- [ ] Swift/Apple
- [ ] Build, packaging, documentation, or qualification evidence

## Protocol and API evidence

Identify the authoritative layout, independent expected frame/vector, or existing contract used.
Do not attach restricted vendor material. State whether the canonical API schema, ABI baseline,
generated bindings, or coverage matrix changed.

## Safety and lifecycle

Describe effects on key lifetime, ownership, serialization, cancellation, callback reentry,
delivery outcome, transaction recovery, and raw/managed transport exclusivity. Write "No change"
when each area is unaffected.

## Verification

| Evidence class | Environment and exact command | Result |
| --- | --- | --- |
| Build and host tests |  |  |
| Sanitizers/static analysis |  |  |
| Binding/package checks |  |  |
| Emulator/cross-compile |  |  |
| Physical card/reader |  |  |

List failures, skipped checks, and their effect. Do not describe a cross-build or replay fixture as
physical hardware evidence.

## Qualification limits

State any remaining unsupported operation, platform, reader, card, key-provider, signing, or
certification boundary introduced or retained by this change.

## Checklist

- [ ] I read `CONTRIBUTING.md` and the engineering standards.
- [ ] This contribution is independently authored and contains no secrets or restricted documents.
- [ ] Public declarations and definitions are documented.
- [ ] Tests use independent expected behavior and cover relevant failure paths.
- [ ] Generated files, API/ABI inventories, coverage, examples, and changelog are updated as needed.
- [ ] I separated host, cross-compile, emulator, physical-device, and production evidence.
