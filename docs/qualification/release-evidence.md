# Release evidence

Each release record contains the source revision, canonical API hash, ABI baseline, compiler
and dependency versions, test preset results, package hashes, export lists, SBOM, notices, and
signing identity. Generated artifacts must be reproducible from the documented toolchain.

Software evidence records debug/release, C++23 compatibility, sanitizers, ABI consumers,
binding conformance, package verification, and soak-test duration. Hardware evidence records
the exact device, OS, reader/firmware, EV3 part/configuration, test-key provenance, frames,
outcomes, and known limitations without recording secrets or personal card data.

The current host C/C++ analyzer scope, findings, fixes, commands, and retained-log hashes are
recorded in [static-analysis.md](static-analysis.md).

The current instrumented concurrency scope, repeated lifecycle tests, and proof limitations are
recorded in [thread-sanitizer.md](thread-sanitizer.md).

The current secret scan, security-oriented source review, dependency advisory triage, sanitizer
cross-check, and machine-readable evidence index are recorded in
[security-scan.md](security-scan.md).

The repository-owned dependency verification, pinned security automation, SBOM generation,
release attestation, update policy, and current supply-chain limits are recorded in
[supply-chain-security.md](supply-chain-security.md).

The current state is maintained in `spec/qualification-record.yaml`. Missing hardware evidence
blocks a production-qualified claim even when host and emulator suites pass.
