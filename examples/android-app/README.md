# DESFire EV3 Showcase for Android

The Showcase is an installable Jetpack Compose integration reference for the Android SDK. It uses
one lifecycle-aware ViewModel, `StateFlow`, foreground NFC dispatch, and an exclusive
`AndroidCardSession` or `AndroidRawSession`. The app depends on the real `sdk/android` Gradle module;
it neither copies SDK source nor implements protocol encoding.

The UI groups practical workflows into six sections:

| Section | Working workflows | Safety boundary |
|---|---|---|
| Discover | GetVersion, application IDs, free memory, application selection | Read-only card operations |
| Authenticate | Standard AES, EV2 First, EV2 NonFirst, ISO AES; Direct, Derived, Provider, and GKey Provider sources | No default keys; all key values are redacted and session-scoped |
| Files | File IDs, settings, and bounded reads | Selected application and matching authentication are explicit prerequisites |
| Transactions | All seven transaction-plan variants: credit, debit, limited credit, write data, write record, update record, and clear record file | Immutable review followed by a second confirmation; never retried |
| Raw | ISO-wrapped native and true ISO 7816 exchange | Managed ownership closes first; exact request is reviewed and runs once on rediscovery |
| Offline | NXP AES-128 derivation and AES transaction MAC | Derived key stays redacted; complete authoritative TMI is caller-supplied |

The screen also packages and searches the canonical `api/ev3-api.json`, so all 120 current ABI
operations remain discoverable by stable ID, domain, summary, mutation status, and input names.
Operation history stays in memory and excludes keys and command payloads.
The raw workflow closes its request and response objects after each exchange; their SDK-owned byte
arrays and the app's temporary response copy are overwritten. Compose text state, IME buffers,
Android runtime copies, or heap dumps can still retain raw input outside that best-effort boundary.

## Build an installable APK

Install Android SDK 37 and NDK `29.0.14206865`, build the three native runtimes, then use the
repository wrapper with strict dependency verification:

```sh
export ANDROID_HOME="/path/to/Android/sdk"
export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865"

python3 sdk/android/tools/build_native.py
./gradlew -p sdk/android --dependency-verification strict \
  --no-daemon --no-build-cache \
  :example-app:assembleDebug :example-app:lintDebug \
  -PdesfireNativeDirectory="$PWD/sdk/android/build/native-jniLibs"
```

The installable debug APK is
`examples/android-app/build/outputs/apk/debug/example-app-debug.apk`:

```sh
adb install -r examples/android-app/build/outputs/apk/debug/example-app-debug.apk
```

Open **DESFire EV3 Showcase**, keep it in the foreground, and present one ISO-DEP card. The Android
host build proves source, shrinker, dependency, and packaging compatibility. NFC RF behavior,
reader firmware, card profile, production keys, and transaction recovery still require validation
on the deployment device and representative physical cards.

## Key custody and recovery

The Showcase contains no default, production, or example key. A user may load exactly one
session-only AES-128 source. The window blocks screenshots, secret fields use password entry and are
not saveable, replaced vault arrays are overwritten, and pause/disconnect clears the vault. Android,
Kotlin, the compiler, or a heap dump can still retain copies outside that best-effort boundary; do
not use production keys in a development APK.

Direct, NXP-derived, callback-provider, and GKey-provider paths call the public Kotlin SDK. The
GKey path requires a caller-owned base key, non-secret reference, and card UID diversification; it
embeds no seed. Provider or key resolution failure occurs before card I/O.

The app closes disposable Direct and Derived key sources after each authentication. Offline NXP
derivation uses Direct/Derived master material or the Provider overload; GKey stays a separate UID
binding strategy. Transaction-MAC calculation honors all four selected source modes and never
bypasses provider resolution.

Every result keeps the SDK error code, delivery outcome, native/ISO status, and reconciliation flag.
An `UNKNOWN` outcome closes and locks the current session. Mutations and raw requests require a
separate review followed by an explicit confirmation, and the app never retries them.
