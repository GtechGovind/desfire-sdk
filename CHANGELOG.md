# Changelog

Notable user-visible changes are recorded here using the Added, Changed, Deprecated, Removed,
Fixed, and Security categories. Versions follow semantic versioning for software compatibility.
A version number does not imply physical-card, reader, platform, or production qualification;
those claims require the separate evidence listed in `docs/testing.md`.

## Unreleased

### Added

- Added contributor, support, conduct, and governance policies plus structured issue and pull
  request templates.
- Rebuilt the README as a developer onboarding guide with architecture, interface selection,
  capabilities, build/install steps, reader integration, key handling, transaction recovery,
  binding evidence, and explicit qualification boundaries.
- Added a documentation index and a complete read-only PC/SC/callback reader integration guide.
- Added cross-platform native and binding pipelines, sanitizer stress runs, CodeQL, dependency
  review, scheduled supply-chain scanning, immutable action pins, and release provenance.
- Added a checksum-pinned Gradle wrapper and strict dependency-verification metadata for the
  Kotlin/JVM and Android builds.

### Changed

- Aligned SDK build commands with the repository Gradle wrapper and strict dependency verification.
- Refreshed Python, Node, native-platform, ABI, dependency, and qualification documentation to
  match the current verified implementation revision.

### Fixed

- Prevented Python 3.14 from reporting unobserved shielded-future exceptions after queued,
  provider, or active card-operation cancellation.

## 0.1.0 - 2026-09-05

- Added the EV3-only C++26 core with a C++23 compatibility build.
- Added native, ISO-wrapped native, and actual ISO 7816 command paths.
- Added managed Standard AES and EV2 First/NonFirst secure messaging, including explicit EV2 First
  PCD capabilities, plus managed ISO AES authentication.
- Added delegated application create/query/delete with issuer-side AES EncK and DAM MAC helpers.
- Added explicit GetCardUID option variants with typed NUID output, RestoreTransfer Plain/MAC
  commands, and offline AES MIFARE Classic license-MAC generation.
- Added versioned C99 and C++17 interfaces plus Python, Node/TypeScript, Kotlin/JVM, Android, and
  Swift facades.
- Added deterministic protocol, crypto, parser, transaction, lifecycle, binding, sanitizer, and
  Android cross-build/package verification.
- Marked SDM, automatic transaction-MAC input construction, SAK/VCIID configuration, PDC, and other
  unverified EV3 capability groups explicitly unavailable.

This is a development release pending physical EV3/reader and production-environment qualification.
