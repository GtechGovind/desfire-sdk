# Security policy

## Reporting a vulnerability

Use the repository's
[private vulnerability reporting form](https://github.com/GtechGovind/desfire-sdk/security/advisories/new).
If that form is unavailable, contact the repository owner privately through the existing project
support channel. Do not open a public issue for a suspected vulnerability.

Include the affected version or revision, platform, reader/card configuration, minimal
reproduction, observed delivery outcome, impact, and sanitized evidence. Remove production keys,
credentials, full card identifiers, payment data, authenticated APDU traces, and restricted
vendor documents. State whether the evidence came from source review, a host or replay test, an
emulator, physical hardware, or production.

The maintainers will coordinate validation, remediation, release guidance, and public disclosure
with the reporter. Public disclosure should wait until affected users have a practical fix or
mitigation. Do not probe systems, cards, readers, or accounts that you do not own or have explicit
authorization to test.

## Supported revisions

Security maintenance covers the active default branch and the latest published release. A release
record must identify its source revision, platform artifacts, checksums, SBOM, and signing or
attestation identity. Development snapshots and older releases receive fixes only when explicitly
listed in a published advisory.

## Runtime security contract

Treat an `unknown` delivery outcome as a possible successful mutation. Persist transaction intent
outside the SDK, reconcile authenticated card and backend state, and never blindly retry a debit,
credit, write, commit, format, delete, or key change. Reader callbacks must not reconnect or retry
internally.

Applications own reader activation, authorization policy, key storage and diversification,
SAM/HSM integration, replay protection, logging, updates, and physical/certification controls. Do
not log APDUs from authenticated sessions or key material. Best-effort in-process erasure cannot
remove copies retained by language runtimes, operating systems, debuggers, or hardware.

SDM, automatic EV3 transaction-MAC input construction, and the other exclusions in
`spec/coverage.md` are unavailable. Do not route security-critical behavior through an unsupported
operation or substitute a raw APDU path that bypasses the managed state machine.

## Dependency and release controls

External GitHub Actions and scanner containers are pinned immutably. The repository owns a
checksum-pinned Gradle wrapper and SHA-256 dependency-verification metadata for both managed build
roots. Dependabot proposes updates; dependency review, CodeQL, scheduled secret and vulnerability
scans, source SBOM generation, and release attestations provide additional gates. The controls,
local verification command, known Gradle build-tool advisories, and proof limits are documented in
`docs/qualification/supply-chain-security.md`.
