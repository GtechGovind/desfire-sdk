# Supply-chain security

The repository owns its Gradle launcher, dependency checksums, scanner configuration, and GitHub
security workflows. These controls make dependency changes reviewable and repeatable. They do not
turn a host build or an automated scan into physical-card, mobile-device, or production
qualification evidence.

## Automated controls

| Control | Trigger | Enforced behavior |
| --- | --- | --- |
| Dependency review | Every pull request | Rejects newly introduced dependencies with known moderate-or-higher advisories. |
| CodeQL | Push, pull request, weekly, or manual | Analyzes C/C++, Kotlin/Java, TypeScript/JavaScript, and Python with extended security queries. |
| Scheduled security scan | Weekly or manual | Scans full Git history for secrets, scans supported manifests with OSV, verifies Gradle checksums, generates source and selected-Gradle CycloneDX SBOMs, and scans both with Grype. |
| Release provenance | Version tag or manual | A tag requires commit-bound software and hardware qualification; a manual run requires commit-bound software evidence only. Both create a deterministic source archive, CycloneDX source SBOM, checksums, and GitHub artifact attestation. |
| Dependabot | Weekly | Proposes reviewed updates for GitHub Actions, Gradle, npm, Python build/test requirements, and Swift packages. |

Each external GitHub Action is pinned to a full commit. Scanner containers are pinned to OCI
index digests so the tag cannot silently select different content. Workflows declare minimum
permissions, checkout never persists the workflow token, and `pull_request_target` is prohibited.
`tools/security/check-supply-chain.py` enforces these repository rules in the scheduled and
release workflows and can be run locally with Python 3.

| Component | Reviewed version | Immutable reference |
| --- | --- | --- |
| GitHub CodeQL Action | 4.37.9 | `cdf488f595d80d6e07e03d4674febd5ab45fa938` |
| GitHub dependency review | 5.0.0 | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |
| GitHub artifact attestation | 4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |
| Gitleaks | 8.30.1 | `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` |
| OSV-Scanner | 2.5.1 | `sha256:dcd947131d8d11b8d0964de6590661fb921a4ecbd7b90a7cb21083acfc3fd8cc` |
| Syft | 1.51.1 | `sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c` |
| Grype | 0.118.0 | `sha256:8a93fc48da96bd6ec5981279d099b69de11541dc68fdf222fb9161f8ff284af7` |
| Android Emulator Runner | 2.38.0 | `a421e43855164a8197daf9d8d40fe71c6996bb0d` |

Dependabot was selected instead of Renovate because it is repository-native, requires no
separate bot credential or hosted application for this scope, and can update full-commit GitHub
Action pins as well as each package ecosystem in the tree. Its pull requests remain subject to
the same dependency review, strict Gradle verification, build, and package checks as other
changes.

Dependency review and CodeQL result upload depend on repository security features available to
the GitHub organization and repository. A workflow configuration passing locally does not prove
that those server-side features are enabled.

## Gradle trust boundary

The root `gradlew` and `gradlew.bat` launch Gradle 9.6.0 for both managed roots:

```text
./gradlew -p sdk/kotlin <tasks>
./gradlew -p sdk/android <tasks>
```

`gradle/wrapper/gradle-wrapper.properties` pins the distribution checksum to
`bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01`. The checked-in wrapper
JAR has SHA-256
`497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7`. Both values are checked
by the repository validator.

Gradle's strict dependency verification reads the repository-owned metadata at:

- `sdk/kotlin/gradle/verification-metadata.xml`
- `sdk/android/gradle/verification-metadata.xml`

Every recorded module, plugin, and metadata artifact has a SHA-256 value. A changed upstream
artifact or an unreviewed dependency fails resolution. When a reviewed dependency update is
intentional, regenerate metadata explicitly, inspect every coordinate and checksum change in the
pull request, and run both roots without the metadata-writing option before merging:

```text
./gradlew -p sdk/kotlin --no-daemon --no-build-cache \
  --write-verification-metadata sha256 dependencies buildEnvironment
./gradlew -p sdk/android --no-daemon --no-build-cache \
  --write-verification-metadata sha256 dependencies buildEnvironment
./gradlew -p sdk/kotlin --dependency-verification strict \
  --no-daemon --no-build-cache dependencies buildEnvironment
./gradlew -p sdk/android --dependency-verification strict \
  --no-daemon --no-build-cache dependencies buildEnvironment
```

Automation never rewrites verification metadata. Checksums verify artifact identity; they do not
prove that a dependency is free of vulnerabilities or malicious behavior.

## Historical build-tool advisory evidence and pending rescan

The retained 2026-09-06 scan of the previous Gradle 8.14.5 and Android Gradle Plugin 8.13.2 graph
reported 85 advisory matches across selected build, instrumentation, and plugin components. Its
four-package Kotlin/Android release runtime graph had no OSV or Grype match. Those counts do not
describe the current Gradle 9.6.0 and Android Gradle Plugin 9.4.0 graph.

In that historical scan, the only direct affected component was Kotlin Gradle plugin 2.3.21 under
`GHSA-r937-wjx7-w2jp`; the first fixed 2.4.20 line was prerelease. An isolated AGP 9.3.2 and Gradle
9.5.0 trial still had 83 selected matches and was not adopted at that time. The source now uses AGP
9.4.0 and Gradle 9.6.0 for API 37, so a fresh commit-bound dependency resolution, SBOM, and advisory
scan is pending. No current advisory count or clean result is claimed.

CI and release commands keep the Gradle build cache disabled while that rescan is pending.
Dependabot surfaces stable candidates, but no update is merged without compilation, package,
dependency-resolution, and managed binding checks. Private transitive versions inside the Android
Gradle Plugin are not forced outside Google's tested graph. The scheduled scan retains a fresh
selected-component Gradle SBOM and Grype result on each run; findings remain visible rather than
being suppressed as if the build graph were clean.

## SBOM and provenance limits

The release workflow's SBOM describes packages Syft can discover from a clean source checkout.
Native libraries built later, the Android NDK, reader drivers, platform frameworks, hardware
firmware, and opaque SAM/HSM components require explicit release inventory. Release artifacts
must add those components and platform binaries to the final SBOM before signing.

GitHub's attestation binds the generated source archive and SBOM digests to the workflow identity
and source revision. It does not sign mobile binaries, prove reproducibility across hosts, certify
protocol behavior, or replace the hardware acceptance record. Release publication must retain
the workflow run, attestation verification output, checksums, dependency notices, and the exact
qualification record.
