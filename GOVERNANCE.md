# Governance

## Project model

The DESFire EV3 SDK is currently a maintainer-led development project. Repository maintainers are
the people granted review, merge, security-triage, or release permissions by the repository host.
No company affiliation, certification authority, or vendor endorsement is implied by that role.

Participants may contribute in these roles:

- **Users** report reproducible behavior and integration needs.
- **Contributors** propose code, tests, documentation, or qualification evidence.
- **Reviewers** assess changes within their demonstrated technical area.
- **Maintainers** accept changes, protect release and security boundaries, and record decisions.

One person may hold several roles. Access is granted according to sustained contribution quality,
sound review judgment, respect for confidential material, and understanding of the protocol and
delivery-safety rules.

## Decisions

Routine implementation and documentation decisions are made through review. Maintainers seek
agreement based on source evidence, independent tests, compatibility, security, and maintainability.
When agreement is not possible, the maintainer responsible for the affected area records the
decision and its tradeoffs in the pull request or architecture documentation.

Changes to the C ABI, canonical operation manifest, protocol interpretation, authentication,
secure messaging, transaction recovery, licensing, or release claims require explicit maintainer
review. They must include relevant compatibility analysis and independent evidence. An undocumented
field layout remains unsupported rather than being accepted by assumption.

Security-sensitive reports may be discussed privately until coordinated disclosure is safe. A
maintainer with a personal or organizational conflict of interest must recuse from the final
decision.

## Compatibility and releases

The canonical API schema, ABI symbol baseline, generated binding inventories, coverage matrix, and
qualification record are repository controls. A release decision must account for all of them.
Semantic versioning describes software compatibility; it does not itself certify hardware,
production keys, transaction recovery, or an integrating product.

Release maintainers follow [the release procedure](RELEASING.md),
[release-evidence requirements](docs/qualification/release-evidence.md), and
[verification matrix](docs/testing.md). Missing physical-device or supply-chain evidence must remain
visible in release notes and blocks a production-qualified claim.

## Governance changes

Governance changes use the normal pull request process and explain why the existing process is no
longer adequate. Maintainers announce material changes in the changelog. New maintainers are
nominated by an existing maintainer and accepted after review by the maintainers with repository
administration responsibility.
