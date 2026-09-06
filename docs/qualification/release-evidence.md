# Release evidence

Each release record contains the source revision, canonical API hash, ABI baseline, compiler
and dependency versions, test preset results, package hashes, export lists, SBOM, notices, and
signing identity. Generated artifacts must be reproducible from the documented toolchain.

Software evidence records debug/release, C++23 compatibility, sanitizers, ABI consumers,
binding conformance, package verification, and soak-test duration. Hardware evidence records
the exact device, OS, reader/firmware, EV3 part/configuration, test-key provenance, frames,
outcomes, and known limitations without recording secrets or personal card data.

The retained 2026-09-06 host C/C++ analyzer scope, findings, fixes, commands, and log hashes are
recorded in [static-analysis.md](static-analysis.md). They precede the current uncommitted changes.

The retained 2026-09-06 instrumented concurrency scope, repeated lifecycle tests, and proof
limitations are recorded in [thread-sanitizer.md](thread-sanitizer.md).

The historical pre-change secret scan, security-oriented source review, dependency advisory triage,
sanitizer cross-check, and machine-readable evidence index are recorded in
[security-scan.md](security-scan.md).

The repository-owned dependency verification, pinned security automation, SBOM generation,
release attestation, update policy, and current supply-chain limits are recorded in
[supply-chain-security.md](supply-chain-security.md).

The current uncommitted source is marked `pending-commit` in
`spec/qualification-record.yaml`. It makes no final scan, package, emulator, or host-test claim.
Update it only with evidence bound to the committed source under test. Missing hardware evidence
blocks a production-qualified claim even when software and emulator suites pass.

`tools/verify-release.py` always checks the qualification schema, canonical API identity, operation
and export counts, evidence state, supply-chain policy, and historical-evidence link. A manual
provenance run requires every software row to be bound to the recorded source commit and marked
`passed`. Version-tag provenance additionally requires the physical EV3, PC/SC reader, Android NFC,
and iOS NFC rows to be `passed`; it rejects an arbitrary revision or any intervening change outside
the qualification-report allowlist.
