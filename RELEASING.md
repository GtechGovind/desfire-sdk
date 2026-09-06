# Releasing

This procedure separates software packaging from physical-card and production qualification. A
development release may ship with explicit limitations. A production-qualified claim requires all
applicable evidence in the qualification record.

## 1. Freeze scope and provenance

- Choose the semantic version and freeze the canonical API manifest and ABI baseline.
- Use a committed source revision. Record the compiler, SDK, operating system, architecture,
  OpenSSL, Android NDK, Swift, JVM, Python, and Node versions used for artifacts.
- Confirm every distributed source and dependency can be redistributed under its recorded license.
  Restricted vendor documents and implementations must remain outside the source archive.
- Resolve or explicitly disposition every release-blocking security, dependency, and qualification
  finding.

## 2. Regenerate and verify source

Regenerate binding inventories, then prove the tree is internally consistent:

```sh
python3 tools/generate-bindings.py
python3 tools/verify-release.py
git diff --check
```

Review generated differences before proceeding. The release verifier checks repository contracts;
it does not replace compilation, dynamic analysis, dependency review, hardware testing, signing, or
artifact inspection.

## 3. Run the software matrix

Run the C++26 debug and release suites, C++23 compatibility, ASan/UBSan, TSan, installed C99/C++17
and modern C++ consumers, API/ABI/coverage/documentation gates, and each binding's conformance and
package checks. Follow [docs/testing.md](docs/testing.md) and retain exact commands and logs.

For every claimed platform, record whether evidence is a host run, cross-compile, emulator or
simulator run, or physical-device run. A successful cross-build proves neither runtime behavior nor
reader/card interoperability.

## 4. Qualify target behavior

Complete the applicable [hardware acceptance matrix](docs/qualification/hardware-acceptance.md)
with the exact card part and configuration, reader and firmware, host or mobile device, test-key
provenance, transaction-recovery behavior, and redacted observed outcomes. Do not store keys,
personal card data, or authenticated session traces in release evidence.

Keep unsupported command groups and unverified platforms visible in `spec/coverage.md` and
`spec/qualification-record.yaml`. Missing evidence blocks only the claim that depends on it; it must
never be silently inferred from another platform.

## 5. Assemble and inspect artifacts

- Produce source packages and applicable Android, Apple, Python, Node, C, and C++ artifacts from the
  recorded revision.
- Verify exported symbols, ABI/manifest identity, target architectures, loader dependencies,
  minimum platform versions, and packaged notices.
- Generate checksums, a dependency inventory or SBOM, license notices, and reproducibility evidence.
- Sign artifacts using the release owner's approved process. This repository contains no signing
  identity or production credentials.
- Install each final artifact into a clean consumer and run its documented smoke test.

## 6. Publish and retain evidence

Move `Unreleased` changelog entries under the dated version. Release notes must state supported
surfaces, breaking changes, migration requirements, security fixes, exact evidence classes, and
remaining qualification limits. Archive checksums, SBOM, signatures, build logs, test results,
hardware records, and rollback instructions with the release.

Development `v0.x.y` tags require complete commit-bound software evidence and must be published as
GitHub pre-releases while physical qualification is incomplete. Stable `v1.0.0` and later tags are
rejected by the provenance workflow until the physical EV3, PC/SC reader, Android NFC, and iOS NFC
rows are all recorded as passed. A pre-release label never changes the evidence recorded for an
artifact.

After publication, verify that consumers can fetch and install the published artifacts. If artifact
identity, ABI checks, signing, or safety behavior differs from the reviewed release, stop promotion
and follow the recorded rollback process rather than replacing evidence in place.
