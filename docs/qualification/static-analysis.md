# Static analysis evidence

This historical record covers source revision
`0f3b733f27b73481f7b26cf9402b64ccfc256e75` on the macOS ARM64 host on 2026-09-06. It does not
describe the current uncommitted source. Fresh commit-bound analysis remains pending. The record
supplements compiler, sanitizer, replay, and hardware evidence; it does not replace any of those
evidence classes.

## Scope

The scan compiled and analyzed 54 production translation units. Headers and included generated
fragments were analyzed through those translation units.

| Domain | Translation units |
| --- | ---: |
| Foundation | 2 |
| EV3 core | 35 |
| OpenSSL provider | 1 |
| Callback, replay, and PC/SC transports | 3 |
| C ABI | 8 |
| Kotlin/JNI bridge | 4 |
| Node N-API bridge | 1 |
| **Total** | **54** |

The root build enabled the OpenSSL provider, PC/SC transport, C ABI, C++17 facade, and
Kotlin/JNI bridge in C++26 mode. The Node module was analyzed from its separate C++17 compile
database. Test and example translation units were excluded from the production count, although
the post-fix release verification compiled and ran them.

## Toolchain

| Tool | Version |
| --- | --- |
| Clang, clang-tidy, and Clang Static Analyzer | Homebrew LLVM 23.1.0 |
| cppcheck | 2.21.0 |
| CMake/CTest | 4.1.2 |
| Ninja | 1.13.2 |
| OpenSSL | 3.6.4 |
| Host | Darwin 25.6.0, ARM64 |

## Results

The clean LLVM build used the repository warning set (`-Wall -Wextra -Wpedantic -Wconversion
-Wshadow`) with `-Werror`. All 53 root/JNI translation units and the Node translation unit
compiled successfully.

Clang Static Analyzer ran its default checkers plus the `security`, `unix`, and `cplusplus`
checker groups through `scan-build`. It reported zero defects in all 54 translation units.

The repository clang-tidy profile initially produced 153 unique root diagnostics and four Node
diagnostics. The root total included 121 repeated C ABI template-instantiation reports for an
exception allocation inside the `noexcept` boundary. After the confirmed fixes, the full scan
contained 31 unique root diagnostics and four Node diagnostics. Manual tracing classified the
remaining reports as follows:

- Five `StackAddressEscape` reports are one Clang analyzer model limitation repeated at each
  return from the provider resolver. `std::stop_callback` unregisters synchronously when its
  automatic object is destroyed, so the registered callback does not survive the function.
  The independent `scan-build` pass reported no defect on the same function.
- Twelve integer-width notices concern compile-time 16 MiB constants whose unsigned products
  are representable before conversion.
- Eight signed-bitwise notices concern well-defined integer promotion of `std::uint8_t` operands
  whose values and shifts remain representable.
- Three empty-catch notices are documented foreign-callback destructor/cancellation boundaries
  that must not throw.
- Two performance notices concern cheap copied `std::stop_token` values.
- One optional-access notice follows a complete prevalidation pass and a successful assignment;
  every error or exception exits before dereference.
- The Node notices cover an exactly caught private exception sentinel, the same representable
  16 MiB constant, and an intentional `unique_ptr::release()` ownership transfer to N-API.

A second warnings-as-errors clang-tidy gate excluded only those explicitly reviewed check
classes and `StackAddressEscape`; it reported zero diagnostics across all 54 translation units.
No broad suppression was added to production source.

The exhaustive cppcheck pass produced 210 root and two Node diagnostics before fixes, and 209
root and two Node diagnostics afterward. The large majority were intentional API/style reports:
implicit `Result<T>` conversions, move-by-value secret ownership, declaration/definition
parameter-name differences, and local naming. A warning/error gate reported zero unsuppressed
findings after two command-line-only model suppressions:

- `DelegatedApplicationConfiguration::application` cannot be default constructed because its
  validated `ApplicationId` has no public default constructor.
- `CommandBuilder::build()` moves all owned storage into `Command`; it returns no reference or
  pointer to the local builder.

## Confirmed fixes

- Added the directly required `<algorithm>` include to the EV2 session implementation. LLVM 23
  had correctly rejected its transitive use of `std::ranges::copy`.
- Replaced allocation of an `Error` inside the C ABI catch-all with an allocation-free fixed POD
  failure writer. An allocation failure can now be reported without attempting another string
  allocation inside a `noexcept` function.
- Validated OpenSSL CBC `used` and `tail` output counts before pointer arithmetic, unsigned
  conversion, and final buffer resize. Partial plaintext is wiped on each invalid provider result.
- Initialized the default `Error::code` to `internal`, removing an uninitialized enum state from
  default construction.
- Added braces to four generated-dispatch loops included by the JNI bridge, matching the
  repository control-flow standard.

All edited C/C++ files pass the repository format and documentation checkers. A fresh LLVM 23
C++26 release build compiled 157 build edges and all 15 host tests passed, including exact-wire,
secure-session, C ABI, C++17, long-exchange, offline, and 100,000-input parser-stress coverage.

## Commands and retained evidence

The principal commands were:

```sh
CC=/opt/homebrew/opt/llvm/bin/clang \
CXX=/opt/homebrew/opt/llvm/bin/clang++ \
cmake -S . -B build/static-proof -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_FLAGS=-Werror -DCMAKE_CXX_FLAGS=-Werror \
  -DDESFIRE_CXX_STANDARD=26 -DDESFIRE_BUILD_TESTS=OFF \
  -DDESFIRE_BUILD_EXAMPLES=OFF -DDESFIRE_BUILD_JNI=ON \
  -DDESFIRE_BUILD_PCSC=ON
cmake --build build/static-proof --parallel

PATH=/opt/homebrew/opt/llvm/bin:$PATH \
run-clang-tidy -p build/static-proof -j 8 -quiet

PATH=/opt/homebrew/opt/llvm/bin:$PATH \
scan-build --status-bugs \
  --use-analyzer=/opt/homebrew/opt/llvm/bin/clang \
  --use-cc=/opt/homebrew/opt/llvm/bin/clang \
  --use-c++=/opt/homebrew/opt/llvm/bin/clang++ \
  -plist-html -enable-checker security -enable-checker unix \
  -enable-checker cplusplus \
  -o build/static-analysis-evidence/scan-build \
  cmake --build build/static-proof --clean-first --parallel 8

cppcheck --project=build/static-proof/compile_commands.json \
  --enable=warning,style,performance,portability --inconclusive \
  --check-level=exhaustive --suppress=missingIncludeSystem --xml
```

The Node commands used `build/static-proof-node/compile_commands.json`. Raw clang-tidy,
scan-build, and cppcheck outputs and the reviewed-gate configuration are retained under
`build/static-analysis-evidence/`.

| Evidence file | SHA-256 |
| --- | --- |
| `clang-tidy-root-final.log` | `0c069b1164588c3dea62a61ee202b9b9412329883fb9e56098ead53e65e5f944` |
| `clang-tidy-node-final.log` | `70a70f767a1ba4a47ff2b466dfb3353e1772a319bdb05478248bd76159c145a5` |
| `clang-tidy-gate-root-final.log` | `f3483dd73d9f73351fffc573085cf01cd65de2ed9562bf79e5023175f0017abe` |
| `clang-tidy-gate-node-final.log` | `97dc34bcfb103a4c1fed8f390b960214b5bcee2e028c074455314b1c883b1216` |
| `scan-build-after-fixes.log` | `a25dd1cb0d042d59b6155874fa520025461204f143a3611f1f2420106e66a303` |
| `scan-build-node.log` | `340475a386928a314bc2ec5a7905f6cc9ea524c80fe56225cc8bff202741961e` |
| `cppcheck-root-after-fixes.xml` | `875bfe11e183b7a11aa52cacce413e37b9e59f82c4fd176e715a063d2b8656dd` |
| `cppcheck-node-after-fixes.xml` | `96b6f4e72c9d79fe4e97708df56ec9c3d7c48db59f26c3ede4569562269019c4` |

## Limits

This is host static-analysis evidence. It does not analyze Android NDK, Linux/GCC, Windows/MSVC,
or Apple cross-target compiler behavior, and it does not prove RF timing, reader firmware,
physical-card behavior, CoreNFC lifecycle, opaque SAM/HSM integration, production signing, or
certification. Static tools can miss defects and can produce false positives; the findings above
were therefore checked against ownership, lifetime, and control-flow semantics rather than
silently discarded.
