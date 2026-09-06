# Dependency and distribution notices

The SDK source is Apache-2.0. The project is independently authored and does not distribute NXP
source, restricted specifications, certificates, card keys, or reader firmware.

The supplied OpenSSL provider requires OpenSSL 3.5 or newer. Desktop builds normally link the
installed OpenSSL Crypto library, which remains governed by its own Apache-2.0 license. The Android
build pins OpenSSL 3.5.8 by version and SHA-256, builds it statically, hides its private symbols, and
packages its full license and upstream copyright section in AAR `META-INF` resources.

The Android AAR packages `libc++_shared.so` for each supported ABI and includes the Android NDK and
toolchain notices. Applications combining native libraries must package exactly one compatible C++
runtime for each ABI. The repository includes the Apache-2.0 Gradle wrapper JAR and launch scripts;
the Gradle distribution is downloaded from its checksum-pinned upstream URL. Kotlin, AndroidX,
Compose, Material 3, Activity, Lifecycle, and coroutines runtime components are Apache-2.0
dependencies of the portable library or showcase APK as declared by Gradle. The Android SDK, NDK,
CMake, Ninja, Perl, Make, Python, Swift, Node.js, and JDK tooling are not redistributed by the source
tree unless a produced package explicitly contains one of their runtime components.

The hosted Windows native matrix copies its freshly built `desfire_c.dll` beside build-tree and
installed-consumer test executables. This avoids relying on shell-specific path conversion when
the Windows loader resolves the tested C ABI library. These copies stay in temporary, non-uploaded
test directories and do not alter the installed SDK package.

PC/SC libraries and operating-system frameworks are optional platform dependencies. The Python
package uses standard-library `ctypes`; the Node addon uses N-API; the Swift package imports the C
ABI as a system library. Review the final binary's dependency list and notices for each release
target because package-manager and platform choices can change what is redistributed.

The opt-in hosted benchmark build downloads the MIT-licensed CodSpeed C++ v2.4.0 compatibility
layer, its `MIT OR Apache-2.0` instrument hooks, and its Apache-2.0 Google Benchmark 1.9.1 fork
from one SHA-256-verified official release asset built from a recorded commit. The CI-only
CodSpeed GitHub Action is MIT-licensed and pinned to a reviewed full commit. These build-only
inputs are disabled by default and are not included in ordinary SDK source or binary packages.
