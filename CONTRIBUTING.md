# Contributing

Thank you for helping improve the DESFire EV3 SDK. Before contributing, read the
[engineering standards](docs/coding-standards.md), [code of conduct](CODE_OF_CONDUCT.md),
[governance](GOVERNANCE.md), and [support policy](SUPPORT.md).

## Before opening a change

Search existing issues and confirm the proposed behavior against the
[coverage matrix](spec/coverage.md). For a protocol change, identify an authoritative field layout
and independent expected bytes or cryptographic values. Raw command access alone does not establish
typed support.

All contributions must be independently authored and suitable for distribution under Apache-2.0.
Do not copy or translate vendor implementations, attach restricted documents, or submit production
keys, personal card identifiers, payment data, or reader credentials. Local restricted references
belong under the ignored `docs/vendor/` directory and must never be force-added.

## Build and test

The default core uses C++26 and retains a C++23 compatibility build. Consumers can use the stable
C99 ABI or the C++17 facade.

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug

cmake --preset compat23
cmake --build --preset compat23 --parallel
ctest --preset compat23
```

Run the checks relevant to your change. Changes to protocol, security, transport lifecycle, or
ownership normally require the sanitizer configurations as well.

```sh
cmake --preset sanitized
cmake --build --preset sanitized --parallel
ctest --preset sanitized

cmake --preset thread-sanitized
cmake --build --preset thread-sanitized --parallel
ctest --preset thread-sanitized

cmake --build build/debug --target format-check docs-check api-check coverage-check
python3 tools/verify-release.py
```

Binding-specific prerequisites and commands are documented in each SDK README. The full host and
target acceptance matrix is in [the verification guide](docs/testing.md).

## Engineering requirements

- Keep public headers self-contained and preserve explicit ownership, cancellation, and recovery
  semantics.
- Never retry a mutation after an uncertain transmission. Preserve `not_sent`, `rejected`,
  `succeeded`, and `unknown` outcomes through every binding.
- Add independent exact-wire, known-answer, malformed-input, state-transition, or lifecycle tests
  as appropriate. Tests that duplicate the implementation do not establish correctness.
- Document every C and C++ declaration and definition according to the engineering standards.
- Update `api/ev3-api.json` and generated binding inventories when the public operation surface
  changes. Generated files must be reproduced by `tools/generate-bindings.py`.
- Update `spec/ev3-command-coverage.yaml` and `spec/coverage.md` when support or qualification
  changes.
- Explain host, cross-compile, emulator, physical-card, reader, and production evidence separately.
  Never promote one evidence class into another.

## Pull requests

Keep a pull request focused on one coherent change. Complete the pull request template with:

1. the concrete problem and resulting behavior;
2. protocol or API evidence used to define the change;
3. ownership, security, delivery-outcome, and compatibility effects;
4. exact commands and environments used for validation; and
5. any physical hardware or platform validation that remains outstanding.

Reviewers may request a smaller change when unrelated generated output, formatting, or refactoring
obscures the behavior under review. Resolve review comments with code, tests, or evidence rather
than deleting an explicit safety check or unsupported-feature boundary.

By intentionally submitting a contribution for inclusion, you provide it under the repository's
[Apache License 2.0](LICENSE), consistent with the license's definition of a Contribution. Mark
communications explicitly as "Not a Contribution" when that is your intent.

## Releases and changelog

Add user-visible changes under `Unreleased` in [CHANGELOG.md](CHANGELOG.md). Classify entries as
Added, Changed, Deprecated, Removed, Fixed, or Security. Release maintainers move those entries to a
dated semantic version only after the required API/ABI, package, license, security, and
qualification evidence is recorded. Follow [RELEASING.md](RELEASING.md). A development package may
be published without a production qualification claim, but its remaining acceptance limits must be
stated plainly.
