# Security scan evidence

## Current commit-bound scan

The 2026-09-06 final source scan is bound to revision
`bb8ec8ece226249bcea55d32aa7b8d68dad9518e`. Its deterministic 407-file Git archive has SHA-256
`fb526ed2912d32b624c513f44a8835fb06376db8615c6ad5f5c1b73fd8df57e1`.

- Gitleaks 8.30.1 found no secret in the archive and no secret in the complete 30-commit history.
- Semgrep Community 1.176.0 ran 112 `p/security-audit` rules over 374 targets and reported no
  finding. It partially parsed `base.h`, `managed.h`, and `raw.h` because of C export and attribute
  macros; strict C99/C11 header compilation, ABI tests, and the native analyzer baseline cover those
  headers independently.
- Syft 1.51.1 identified 50 components in the source SBOM; Grype 0.118.0 reported no match.
- npm audit and OSV-Scanner reported no Node advisory.
- The selected Gradle build and instrumentation graph contains 175 components and seven known
  matches: two high and five medium. These are build-host dependencies and are absent from the
  shipped Kotlin/Android runtime graph. The exact affected packages and remediation constraints are
  recorded in [supply-chain-security.md](supply-chain-security.md).

The same source passed C++23/C++26 host tests, ASan/UBSan, TSan, binding suites, Android package
verification, and Swift 6 iOS device/simulator source compilation. Those results and package
digests are indexed in `spec/qualification-record.yaml`. Physical EV3, PC/SC, Android NFC, and
CoreNFC acceptance remain unrun.

## Retained historical scan

This is retained historical evidence from the macOS ARM64 qualification run on 2026-09-06. It is
associated with source revision `0f3b733f27b73481f7b26cf9402b64ccfc256e75` and canonical API hash
`f54fa5c36cbf171f3b4381f34786a73a4ed2b9ca20ec74b68d9efb11c5ac01ff`. All uses of “current” in
the retained text below refer to that historical scan snapshot.

The retained evidence is bound to the historical source snapshot in
`build/security-scan/source-manifest.sha256`. The manifest covers 373 of the 374 then-existing
non-ignored files and has SHA-256
`40d387ccab9bd702ce1e0e076fa48ce1841b19e807a79eab2c473cc794f9cbc9`.
It excludes this report because embedding the manifest hash in a file covered by that manifest
would be self-referential. Gitleaks separately scanned all 374 files, including this report.

## Result

No secret was found in the current non-ignored source. No known vulnerability was reported in
the Node lockfile, the four-package Kotlin/Android release runtime graph, or the source SBOM.
The source scan confirmed and fixed one same-channel ISO callback reentry deadlock and one reset
exception-boundary defect. The current source then passed the normal, AddressSanitizer,
UndefinedBehaviorSanitizer, and ThreadSanitizer suites.

The first hosted CodeQL pass also identified unsafe standard-library tar extraction and a
potential regular-expression denial of service in repository tooling. Archive extraction now
writes only validated regular files, and documentation detection uses bounded linear scans.

Hosted Windows C++23 and C++26 qualification initially presented as 180-second C ABI consumer
timeouts. Direct phase instrumentation established that every DLL-importing consumer terminated
before its first statement with Windows status `0xC0000135`, while compile-only and non-importing
controls passed. Staging the exact Visual C++ 14.51 runtime beside the executable did not change
that status, disproving the earlier OpenSSL teardown hypothesis. The Git Bash loader path was not
a native Windows path, so the workflow now copies the exact build-tree or installed
`desfire_c.dll` beside each affected test executable before it runs. OpenSSL retains its default
process-lifecycle behavior.

The Git-history scan matched five published cryptographic known-answer vectors in the archived
pre-EV3 test suite. Each reviewed false positive is suppressed by its exact commit, path, rule,
and line fingerprint in `.gitleaksignore`; broader path or rule suppression is not used.

The Gradle build and Android instrumentation tool graph is not advisory-clean. Its selected
components produce 85 advisory matches across 20 package/version pairs and 47 unique GHSA IDs.
These components are absent from the published Kotlin/Android runtime graph, but they execute on
the build host. This prevents a clean build-supply-chain claim. The exact raw and triaged records
are retained in `build/security-scan/gradle-advisory-triage.json`.

## Scope and tools

The secret scan used an exact snapshot of all 374 existing files returned by
`git ls-files --cached --others --exclude-standard`, totaling 3,493,043 bytes. SAST covered the
foundation, core, OpenSSL provider, transports, C ABI, SDK bridges, build tools, examples, and
tests. The compile-database passes independently covered 49 native production translation units;
the broader LLVM scan in [static-analysis.md](static-analysis.md) covered 54 production
translation units including JNI and Node.

| Tool | Version | Scope |
| --- | --- | --- |
| Apple Clang Static Analyzer | AppleClang 21.0.0 | 49 native production translation units |
| Clang Static Analyzer and clang-tidy | Homebrew LLVM 23.1.0 | 54 production translation units; see `static-analysis.md` |
| cppcheck | 2.21.0 | 49 native production translation units |
| Semgrep Community | 1.176.0 | 112 security-audit rules over 261 source targets |
| Gitleaks | 8.30.1 | 374 non-ignored working-tree files |
| OSV-Scanner / OSV-Scalibr | 2.5.1 / 0.5.2 | Node lockfile and CycloneDX source, Gradle, and runtime SBOMs |
| Syft | 1.51.1 | Current-source CycloneDX SBOM |
| Grype | 0.118.0 | Current-source, Gradle selected, and managed-runtime SBOMs |
| npm | 11.12.1 | Node package-lock audit |
| Gradle | Historical proof executable 8.14.5 | Android/Kotlin dependency resolution only |
| CMake / Ninja | 4.1.2 / 1.13.2 | C++26 build and test |
| OpenSSL | 3.6.4 | Host provider used by the proof build |

The historical dependency proof used an external Gradle 8.14.5 executable. The repository now
carries a Gradle 9.6.0 wrapper with the upstream distribution and wrapper-JAR checksums pinned,
plus strict SHA-256 dependency-verification metadata for both managed build roots. The retained
advisory counts below apply only to the historical Gradle 8.14.5 and Android Gradle Plugin 8.13.2
graph; the current-graph result is recorded above.

## SAST and manual review

| Pass | Raw result | Triage |
| --- | ---: | --- |
| LLVM 23 `scan-build`, default + security + unix + cplusplus | 0 | Clean |
| LLVM 23 reviewed clang-tidy warning/error gate | 0 | Clean |
| AppleClang `--analyze` | 5 | One `std::stop_callback` model false-positive family |
| cppcheck warning/performance/portability exhaustive | 12 | 2 model false positives; 10 intentional ownership copies |
| Semgrep `p/security-audit` | 1 | Pinned HTTPS download false positive |
| Gitleaks | 0 | Clean |
| Manual unsafe API and logging pattern review | 30 candidates | No unbounded or secret-logging defect confirmed |

The five Apple analyzer `core.StackAddressEscape` reports occur at five returns from
`resolve_once()` in `core/src/managed/card_authentication.cpp`. They are false positives.
The two automatic `std::stop_callback` objects are declared after the local `stop_source`; C++
destroys them first in reverse construction order, and each destructor synchronously unregisters
its callback before the referenced stop source can be destroyed. Neither callback, token, nor
reference is returned or retained. Provider-cancellation tests independently trigger request and
operation cancellation during resolution and verify both cancellation observation and zero card
I/O. LLVM 23 `scan-build` reports zero defects on the same function.

Cppcheck's `returnDanglingLifetime` report is false because `CommandBuilder::build()` moves its
owned header and secure payload into the returned `Command`; no view into the builder survives.
Its `uninitMemberVarNoCtor` report is false because the validated `ApplicationId` member is not
default constructible. The ten performance notices recommend references for parameters that
intentionally take ownership of move-only secret keys or request state.

Semgrep reports dynamic `urllib` use at `sdk/android/tools/build_native.py:77`. The URL is made
only from the compile-time `OPENSSL_VERSION`, uses HTTPS, and the downloaded archive must match
the pinned SHA-256 before extraction. Extraction separately rejects path traversal, escaping
links, and special devices. There is no caller-controlled URL. Semgrep partially parsed three C
headers containing C attribute/export macros, so the LLVM and cppcheck compile-database passes
remain the primary analysis evidence for those headers.

The manual pattern pass found three `strcpy` candidates: two copy fixed 23- and 31-byte literals
into the 246-byte `df_error.message` array, and one is a bounded test fixture. Twenty-two raw
memory candidates use an explicitly checked capacity, a fixed POD size, or a fixed 16-byte key
buffer. The four logging candidates either print only a derived key's size, print a redacted
error, or are documentation that explicitly forbids secret logging. No production path logs an
AES key, key reference, diversification input, session key, or authentication token.

The broader LLVM findings and the shared-source fixes to the C ABI exception boundary, OpenSSL
CBC output validation, `Error::code` initialization, EV2 include ownership, and JNI generated
loops are documented in [static-analysis.md](static-analysis.md).

## Confirmed ISO channel fix

`iso7816::raw::Channel` previously held a non-recursive mutex while calling the user-supplied
transport. If that callback invoked `exchange()` or `reset()` on the same channel on the same
thread, the process deadlocked before it could report `busy`. A throwing transport `reset()`
could also escape the core exception boundary.

The channel now uses a recursive admission mutex plus an RAII activity marker. Nested exchange
and reset calls return `ErrorCode::busy` with `Outcome::not_sent`; the outer exchange completes,
and the channel remains usable. `reset()` now contains arbitrary transport exceptions and
returns `internal` with `Outcome::unknown`. `ev3_iso7816_test` includes a transport that attempts
both reentry paths from inside its exchange callback.

## Sanitizers and tests

A current C++26 Debug build compiled 144 rebuilt edges and passed all 15 host tests. The same
source passed all 15 AddressSanitizer/UndefinedBehaviorSanitizer tests with
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Apple ASan rejects `detect_leaks=1` on this
host before running a test, so leak detection is not part of this evidence.

The current ThreadSanitizer build passed all 15 tests, then repeated the ISO channel, C ABI,
long-exchange, and managed-card tests 20 times each, for another 80 executions with zero TSan
diagnostics. The exact scope and limitations are in
[thread-sanitizer.md](thread-sanitizer.md).

## Dependency results

| Surface | Resolved content | OSV | Grype | Assessment |
| --- | ---: | ---: | ---: | --- |
| Node lockfile | 3 dependencies | 0 | n/a | No known advisory; all are development dependencies |
| Kotlin/Android release runtime | 4 selected Maven artifacts | 0 | 0 | No known advisory in the shipped managed runtime graph |
| Python runtime | 0 third-party dependencies | n/a | n/a | Standard library and C ABI only |
| Swift package | 0 external Swift packages | n/a | n/a | C ABI system library only |
| Current-source Syft SBOM | 2 discovered components | 0 | 0 | Limited discovery; native dependency caveat below |
| Full selected Gradle graph | 255 components | 85 | 85 | Build/instrumentation/plugin findings remain |

The Android script pins OpenSSL 3.5.8 and its official archive SHA-256. The host build resolved
OpenSSL 3.6.4. Syft did not model these native dependencies as OSV-addressable packages, so a zero
source-SBOM result is not proof that those OpenSSL releases have no applicable advisory. Release
verification must keep the pinned OpenSSL release and NDK inventory explicit and reassess them
against the release-date vendor advisories.

The first deliberately over-inclusive Gradle SBOM retained both requested and selected versions
and produced 107 raw matches: 1 critical, 47 high, 52 medium, and 7 low. Exact Gradle resolution
shows that 22 of those rows are superseded requests, including old Gson, Guava, HttpClient,
Kotlin stdlib, and protobuf versions that are not present in the selected graph. The remaining
85 selected rows are 1 critical, 37 high, 43 medium, and 4 low.

Only `org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.21` is a direct selected vulnerable build
dependency. `GHSA-r937-wjx7-w2jp` concerns unsafe deserialization of malicious build-cache
metadata. All proof commands explicitly disabled the Gradle build cache. The newest stable Kotlin
release available during this proof was 2.4.10 according to the
[Kotlin release history](https://kotlinlang.org/docs/releases.html), while the advisory's first
fixed build was 2.4.20-Beta1 and the
[available plugin line](https://plugins.gradle.org/plugin/org.jetbrains.kotlin.jvm/2.4.20-RC3)
was still at 2.4.20-RC3. A prerelease compiler/plugin was not introduced into the production build
to silence the scanner.

The other 84 selected rows are transitive dependencies of Android Gradle Plugin 8.13.2 and its
Unified Test Platform, emulator, bundletool, Jetifier, archive, signing, and networking tools.
Their code is absent from the AAR and Kotlin/JVM runtime classpaths. Archive parsing, Jetifier XML,
bundletool JWE, certificate processing, and instrumentation network traffic can still exercise
parts of this code on a build host, so these findings are not dismissed as harmless.

An isolated upgrade trial used current stable
[Android Gradle Plugin 9.3.2](https://developer.android.com/build/releases/agp-9-3-0-release-notes)
and its required Gradle 9.5.0. It required removing the external Kotlin Android plugin and migrating
the source-set DSL. `compileReleaseKotlin` then passed, but the selected build graph still produced
83 matches and introduced affected built-in Kotlin Gradle plugin 2.2.10 plus Commons Lang and
HttpClient rows. The trial reduced only two matches while requiring a major build migration, so it
was not applied. Forcing versions of AGP's private transitive dependencies would be outside
Google's tested plugin graph and was also not applied.

The 47 unresolved selected advisory IDs are:

- Critical: `GHSA-574f-3g2m-x479`.
- High: `GHSA-2363-cqg2-863c`, `GHSA-3677-xxcr-wjqv`, `GHSA-3qp7-7mw8-wx86`,
  `GHSA-4g8c-wm8x-jfhw`, `GHSA-558v-64gr-wgg4`, `GHSA-57rv-r2g8-2cj3`,
  `GHSA-6jqx-86gh-f27w`, `GHSA-735f-pc8j-v9w8`, `GHSA-93wv-jw9v-4972`,
  `GHSA-c653-97m9-rcg9`, `GHSA-f6hv-jmp6-3vwv`, `GHSA-jppx-w49h-x2qq`,
  `GHSA-mj4r-2hfc-f8p6`, `GHSA-mvh2-crg5-v77c`, `GHSA-prj3-ccx8-p6x4`,
  `GHSA-pwqr-wmgm-9rr8`, `GHSA-w9fj-cfpg-grvv`, `GHSA-x4gw-5cx5-pgmh`, and
  `GHSA-xpw8-rcwv-8f8p`.
- Medium: `GHSA-389x-839f-4rhx`, `GHSA-38f8-5428-x5cv`, `GHSA-3p8m-j85q-pgmj`,
  `GHSA-4265-ccf5-phj5`, `GHSA-4g9r-vxhx-9pgx`, `GHSA-4mp9-239f-g9hg`,
  `GHSA-563q-j3cm-6jxm`, `GHSA-5jpm-x58v-624v`, `GHSA-5x3r-wrvg-rp6q`,
  `GHSA-6cqp-g7gg-8hr5`, `GHSA-6mjq-h674-j845`, `GHSA-84h7-rjj3-6jx4`,
  `GHSA-8c42-7qj2-3j46`, `GHSA-c2gf-v879-257j`, `GHSA-c3fc-8qff-9hwx`,
  `GHSA-c69g-56f8-xwqj`, `GHSA-gcjf-9mgh-3p7g`, `GHSA-hvcg-qmg6-jm4c`,
  `GHSA-m4cv-j2px-7723`, `GHSA-q4f6-jm68-57ww`, `GHSA-r937-wjx7-w2jp`,
  `GHSA-v8h7-rr48-vmmv`, `GHSA-wg6q-6289-32hp`, `GHSA-xq3w-v528-46rv`, and
  `GHSA-xxqh-mfjm-7mv9`.
- Low: `GHSA-45q3-82m4-75jr` and `GHSA-fghv-69vj-qj49`.

The machine-readable triage records every one of the 107 rows with Maven coordinate, direct or
transitive classification, selected or superseded state, Gradle configuration, severity, GHSA
and CVE aliases, reachability, fixed versions, and disposition.

## Retained evidence

| Evidence | SHA-256 |
| --- | --- |
| `build/security-scan/source-manifest.sha256` | `40d387ccab9bd702ce1e0e076fa48ce1841b19e807a79eab2c473cc794f9cbc9` |
| `build/security-scan/gitleaks.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `build/security-scan/semgrep.json` | `f8ab24ace967dfa1b44de1c5f7c61861bbcc519add022b71e4206fdb7d8d0785` |
| `build/security-scan/clang-analyzer.log` | `12cc5aa0eb64fc0cb12f124cb9d910641355041ad2da0a7411e07335111b6f2d` |
| `build/security-scan/cppcheck-production.xml` | `07ce6bb36fdb3d648206f3067496b33b3213145c829662c9f7e7b1de1e85a41e` |
| `build/security-scan/npm-audit.json` | `f9a031af1fd5991a41d6dbf8c4fcafa5b596b094a7d17ad5dea052518cd16fb7` |
| `build/security-scan/source-sbom.cdx.json` | `120ca9a3df359110c2051ae09d2816c471fd10160fdd3e8c10d7100772114cd9` |
| `build/security-scan/grype-source.json` | `66de0d87b500ef2a945e5fa9e5e4b469fa1a1c8e87c14d45c1b34ac6f046b9f8` |
| `build/security-scan/gradle-advisory-triage.json` | `23850d63a4ba99b467cd239d039c96a85ecaa714d326de898508f15442b01dbf` |
| `build/security-scan/grype-gradle-selected.json` | `e30490d3ca3decdd5ea4e144080eceacdeb70235e04783c5a1c0f7f8a6e8ee52` |
| `build/security-scan/grype-gradle-runtime.json` | `cfb68eb8d4152e4bdac91a50d44c6cf8111383e05eeb6a53029de983ad24d5af` |
| `build/sanitized/ctest-asan-ubsan-post-fix.log` | `fc2b6b3b7536bb94f2cca351126cffe476aee0e91fc63ccfc3de2570485dff1d` |
| `build/tsan-proof/ctest-tsan-post-fix.log` | `d637b47290f2f56df39969ca3220acf9e89caa14e19f5268b3c171fbeedb9f8e` |
| `build/security-scan/supply-chain-policy.log` | `7445c0306332c62ce09e3727fd5ca1ec79fdea9947803626acd7d02e1a4b3e3b` |
| `build/security-scan/actionlint.log` | `ff93ab849e82ed3e0f9583169b78de6e9e827ddd4340a9a2ffa241a9348073f7` |
| `build/security-scan/gradle-kotlin-strict.log` | `a1c0bcb35996fd993ab4d549f35e17abae37b79331fea039cda4effaa5c35f97` |
| `build/security-scan/gradle-android-strict.log` | `17a2a0f38ecf78f760f210075c2bfbb13a0b547c68dec852e8381dc57ac8bb8e` |
| `build/security-scan/gradle-selected-current.cdx.json` | `adbfaa65c4f26654b70a2b4cd04d5981c190eb86f5bdc4d334e1e6b0c529b5ad` |
| `build/security-scan/grype-gradle-selected-current.json` | `f690b9a0d3f629ff4e1312827018174e42ef55c99bb29798b8effaba916ec34a` |
| `gradle/wrapper/gradle-wrapper.jar` | `7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172` |
| `sdk/android/gradle/verification-metadata.xml` | `4b9167942b09380721bf72a73d6fce8faf43d63613a93dd19ce7649480bbf8f7` |
| `sdk/kotlin/gradle/verification-metadata.xml` | `ee3f048db9ffa8962635f14c1eb0f0049a36823f28fc9d749fab0f3caedadfc2` |

## Limits and release decision

These scans cannot prove EV3 protocol semantics, cryptographic side-channel resistance, compiler
behavior on Android/iOS/Linux/Windows, physical-card behavior, RF timing, reader firmware,
CoreNFC or IsoDep lifecycle, production key custody, opaque SAM/HSM behavior, or certification.
SAST can miss defects; dependency scanners can lag vendor disclosures and report code paths that
are not reachable. Secret scanning cannot prove that a secret was never present outside the
current non-ignored snapshot.

The host source and shipped managed-runtime dependency results are clean after the confirmed fix.
The repository is not yet release-qualified because the Gradle build-tool advisory set remains,
the native dependency inventory is not fully machine-resolved, and the hardware-acceptance matrix
is still required. The repository-owned Gradle wrapper and strict dependency-verification metadata
close the earlier artifact-identity gap but do not remediate those advisories.
