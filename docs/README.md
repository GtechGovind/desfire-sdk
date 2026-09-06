# DESFire EV3 SDK documentation

Use this page to find the contract, example, or qualification evidence for the part of the SDK
you are integrating. The root [README](../README.md) gives the product overview and shortest build
path; this index covers the detailed engineering material.

## Start integrating

| Goal | Read this first | Continue with |
| --- | --- | --- |
| Build and install the native SDK | [Build and packaging](build.md) | [Examples](../examples/README.md), [testing](testing.md) |
| Choose a language interface | [API contract](api-contract.md) | [C](bindings/c.md), [C++17](bindings/cpp17.md), [Kotlin/Android](bindings/kotlin-android.md), [Python](bindings/python.md), [Node/TypeScript](bindings/node-typescript.md), [Swift](bindings/swift.md) |
| Integrate an NFC reader | [Reader integration](reader-integration.md) | [Transport lifecycle](architecture/transport-lifecycle.md), [native protocol](architecture/native-protocol.md) |
| Find a supported command | [Implementation matrix](../spec/coverage.md) | [Canonical API manifest](../api/ev3-api.json), generated Doxygen reference |
| Add authentication or key resolution | [Key resolution](architecture/key-resolution.md) | [Security profiles](architecture/security-profiles.md) |
| Use exact APDUs or native frames | [Raw and managed APIs](architecture/raw-and-managed-apis.md) | [Native protocol](architecture/native-protocol.md), [API contract](api-contract.md) |
| Decide whether a target is production-ready | [Qualification record](../spec/qualification-record.yaml) | [Hardware acceptance](qualification/hardware-acceptance.md), [release evidence](qualification/release-evidence.md) |

## Understand the design

| Document | What it defines |
| --- | --- |
| [Architecture overview](architecture.md) | Module boundaries, ownership, layering, and transport exclusivity |
| [Core layers](architecture/core-layers.md) | Foundation, protocol, checked, managed, provider, transport, and ABI responsibilities |
| [Native protocol](architecture/native-protocol.md) | Direct and ISO-wrapped framing, additional frames, lengths, and status handling |
| [Raw and managed APIs](architecture/raw-and-managed-apis.md) | Exact exchange versus typed workflows, state ownership, outcomes, and recovery |
| [Security profiles](architecture/security-profiles.md) | Standard AES, EV2, ISO AES, communication modes, and session transitions |
| [Key resolution](architecture/key-resolution.md) | Direct, derived, and provider keys plus lifetime and logging rules |
| [GKey derivation](architecture/gkey-derivation.md) | Optional Kotlin compatibility layout, provider lifecycle, and synthetic vectors |
| [Transport lifecycle](architecture/transport-lifecycle.md) | Activation, callbacks, FIFO admission, cancellation, close, and reconnect rules |

The Doxygen reference is generated from the same documented public C/C++ headers and
definitions used by the build. Configure a build and run:

```sh
cmake -S . -B build/documentation -G Ninja \
  -DDESFIRE_CXX_STANDARD=23 \
  -DDESFIRE_BUILD_PCSC=OFF
cmake --build build/documentation --target docs docs-check
```

Open `build/documentation/documentation/html/index.html` after the `docs` target completes.

## Language guides

The documents under `docs/bindings` define each binding's public contract and parity rules. The
SDK-local README files contain package-specific build and runtime instructions.

| Language | Contract | Package instructions |
| --- | --- | --- |
| C | [C binding](bindings/c.md) | [`c-api`](../c-api/README.md) |
| C++17 | [C++17 facade](bindings/cpp17.md) | [`sdk/cpp17`](../sdk/cpp17/README.md) |
| Kotlin/JVM | [Kotlin and Android](bindings/kotlin-android.md) | [`sdk/kotlin`](../sdk/kotlin/README.md) |
| Android | [Kotlin and Android](bindings/kotlin-android.md) | [`sdk/android`](../sdk/android/README.md) |
| Python | [Python](bindings/python.md) | [`sdk/python`](../sdk/python/README.md) |
| Node/TypeScript | [Node and TypeScript](bindings/node-typescript.md) | [`sdk/node`](../sdk/node/README.md) |
| Swift | [Swift](bindings/swift.md) | [`sdk/apple`](../sdk/apple/README.md) |

## Verify and release

| Evidence | Purpose |
| --- | --- |
| [Testing and qualification](testing.md) | Reproducible local commands, recorded host evidence, and target acceptance checklist |
| [Coverage rules](qualification/coverage.md) | Criteria for calling a command or binding implemented |
| [Implementation matrix](../spec/coverage.md) | Current feature, test, platform, and unsupported-scope record |
| [Static analysis](qualification/static-analysis.md) | Analyzer scope, reviewed diagnostics, fixes, and limits |
| [ThreadSanitizer](qualification/thread-sanitizer.md) | Instrumented translation units, repeated race scenarios, and limits |
| [Security scan](qualification/security-scan.md) | Secret scan, SAST, dependency triage, and retained evidence hashes |
| [Supply-chain security](qualification/supply-chain-security.md) | Pinned actions, dependency verification, SBOM, and advisory policy |
| [Hardware acceptance](qualification/hardware-acceptance.md) | Required card, reader, RF, Android, and Apple device evidence |
| [Release evidence](qualification/release-evidence.md) | Required provenance, package, signing, and qualification records |
| [Release procedure](../RELEASING.md) | Versioning, artifact generation, validation, signing, and publication steps |

Passing host or replay tests is software evidence. It does not establish behavior on a physical
EV3 card, reader firmware, RF link, mobile NFC stack, production key system, or certified product.

## Contribute safely

1. Read the [contribution guide](../CONTRIBUTING.md) and [coding standards](coding-standards.md).
2. Update the canonical schema and coverage matrix when a public operation changes.
3. Add independent success, failure, malformed-input, ownership, and outcome tests as applicable.
4. Run formatting, documentation, API, ABI, package-consumer, and relevant sanitizer checks.
5. Keep undocumented layouts fail-closed and record unresolved qualification boundaries.

Never commit AES keys, production or private diversification inputs, personal card data, restricted
vendor documents, or reader credentials. Public synthetic test vectors may be committed when they
contain no deployed material. Report suspected vulnerabilities through [SECURITY.md](../SECURITY.md).
