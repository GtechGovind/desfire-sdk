# ThreadSanitizer evidence

This record covers the native production implementation on the macOS ARM64 host on
2026-09-06. ThreadSanitizer evidence complements static analysis, AddressSanitizer,
UndefinedBehaviorSanitizer, replay tests, and target acceptance.

## Instrumented scope

A fresh C++26 Debug build compiled all 152 Ninja edges with AppleClang 21.0.0 and
`-fsanitize=thread -fno-omit-frame-pointer`. The compile database confirmed that all 49
production C++ translation units were instrumented. `otool` found
`libclang_rt.tsan_osx_dynamic.dylib` in the test executables and C ABI shared library, and `nm`
found the expected `__tsan_*` hooks.

The build was created with:

```sh
cmake -S . -B build/tsan-proof -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DDESFIRE_CXX_STANDARD=26 \
  -DDESFIRE_ENABLE_TSAN=ON \
  -DDESFIRE_BUILD_TESTS=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build/tsan-proof --parallel 10
```

## Results

The stabilized post-analysis source passed all 15 tests with immediate abort on any TSan
diagnostic. The suite includes 100,000 deterministic parser inputs. The ISO channel, C ABI,
long-exchange, and managed-card tests then passed 20 consecutive repetitions each, for 80
additional executions. This repetition includes the same-channel ISO callback reentry regression.

```sh
env TSAN_OPTIONS=halt_on_error=1:abort_on_error=1:second_deadlock_stack=1 \
  ctest --test-dir build/tsan-proof --output-on-failure --timeout 300 -j 1

env TSAN_OPTIONS=halt_on_error=1:abort_on_error=1:second_deadlock_stack=1 \
  ctest --test-dir build/tsan-proof --output-on-failure --timeout 300 -j 1 \
  --repeat until-fail:20 \
  -R '^(ev3_iso7816_test|ev3_long_exchange_test|ev3_card_test|c_abi_test)$'
```

The retained log contains zero ThreadSanitizer warnings, race summaries, errors, or test
failures. It is stored at `build/tsan-proof/ctest-tsan-post-fix.log` with SHA-256
`d637b47290f2f56df39969ca3220acf9e89caa14e19f5268b3c171fbeedb9f8e`.

## Limits

ThreadSanitizer observes only schedules reached by the host tests. It cannot prove that every
interleaving is safe, and it does not cover Android, iOS, Windows, reader-firmware threads,
physical-card removal timing, RF behavior, opaque SAM/HSM providers, or integrating-application
callbacks that are absent from the replay fixtures.
