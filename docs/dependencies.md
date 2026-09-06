# Dependency and distribution notices

The SDK source is Apache-2.0. The project is independently authored and does not distribute NXP
source, restricted specifications, certificates, card keys, or reader firmware.

The supplied OpenSSL provider requires OpenSSL 3.5 or newer. Desktop builds normally link the
installed OpenSSL Crypto library, which remains governed by its own Apache-2.0 license. The Android
build pins OpenSSL 3.5.8 by version and SHA-256, builds it statically, hides its private symbols, and
packages its full license and upstream copyright section in AAR `META-INF` resources.

The Android AAR packages `libc++_shared.so` for each supported ABI and includes the Android NDK and
toolchain notices. Applications combining native libraries must package exactly one compatible C++
runtime for each ABI. Kotlin, Kotlin coroutines, AndroidX test libraries, Gradle, the Android SDK,
the NDK, CMake, Ninja, Perl, Make, Python, Swift, Node.js, and JDK tooling are not redistributed by
the source tree unless a produced package explicitly contains one of their runtime components.

PC/SC libraries and operating-system frameworks are optional platform dependencies. The Python
package uses standard-library `ctypes`; the Node addon uses N-API; the Swift package imports the C
ABI as a system library. Review the final binary's dependency list and notices for each release
target because package-manager and platform choices can change what is redistributed.
