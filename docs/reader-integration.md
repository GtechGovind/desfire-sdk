# Reader integration

The SDK starts after the operating system or application has discovered a reader and activated a
card. A transport owns that activation and sends each physical frame exactly once. The core owns
DESFire framing, additional-frame exchange, authentication state, and command serialization.

## Choose a transport

| Reader interface | SDK transport | Framing |
| --- | --- | --- |
| Desktop PC/SC | `desfire::transports::pcsc_provider()` | ISO APDUs through the system PC/SC stack |
| Existing vendor SDK | `desfire::transports::CallbackTransport` | Direct native or ISO-wrapped, according to declared capabilities |
| C or managed binding | Language-specific callback transport | Same explicit framing and size limits as the C++ callback adapter |
| Tests and deterministic reproduction | `desfire::transports::ReplayTransport` | Exact expected request/response fixtures |
| Android | `IsoDepTransport` | ISO-wrapped native and ISO 7816 APDUs over connected `IsoDep` |
| Apple | `DesfireEV3CoreNFC` | ISO-wrapped native and ISO 7816 APDUs over the active CoreNFC tag |

ISO-DEP fragmentation belongs to the platform reader stack. DESFire `0xAF` additional frames
belong to the core. Do not split or combine those layers in the application callback.

## Read a card with PC/SC

This modern C++ example enumerates readers, opens the first available endpoint, and performs the
read-only GetVersion operation:

```cpp
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/managed/card.hpp>
#include <desfire/transports/pcsc.hpp>

#include <iostream>

namespace {
int fail(const desfire::Error& error) {
    std::cerr << "DESFire error code=" << static_cast<unsigned>(error.code)
              << " outcome=" << static_cast<unsigned>(error.outcome)
              << " status=0x" << std::hex << error.device_status
              << " message=" << error.message << '\n';
    return 1;
}
} // namespace

int main() {
    auto provider = desfire::transports::pcsc_provider();
    if (!provider) {
        return fail(provider.error());
    }

    auto readers = provider.value()->readers();
    if (!readers) {
        return fail(readers.error());
    }
    if (readers.value().empty()) {
        std::cerr << "No PC/SC reader is available\n";
        return 2;
    }

    auto transport = provider.value()->open(readers.value().front().id);
    if (!transport) {
        return fail(transport.error());
    }

    auto crypto = desfire::openssl_provider();
    if (!crypto) {
        return fail(crypto.error());
    }

    auto card = desfire::ev3::managed::Card::connect(transport.value(), crypto.value());
    if (!card) {
        return fail(card.error());
    }

    auto version = card.value()->get_version();
    if (!version) {
        return fail(version.error());
    }

    std::cout << "Vendor: " << static_cast<unsigned>(version.value().hardware.vendor)
              << ", hardware " << static_cast<unsigned>(version.value().hardware.major)
              << '.' << static_cast<unsigned>(version.value().hardware.minor)
              << ", software " << static_cast<unsigned>(version.value().software.major)
              << '.' << static_cast<unsigned>(version.value().software.minor) << '\n';
}
```

A minimal consumer target is:

```cmake
cmake_minimum_required(VERSION 3.25)
project(ev3_reader LANGUAGES CXX)

find_package(desfire-sdk CONFIG REQUIRED)

add_executable(ev3_reader main.cpp)
target_compile_features(ev3_reader PRIVATE cxx_std_23)
target_link_libraries(ev3_reader PRIVATE
    desfire::ev3_core
    desfire::crypto_openssl
    desfire::transport_pcsc)
```

Build the SDK with `DESFIRE_BUILD_PCSC=ON`, install it, and point the consumer at that prefix:

```sh
cmake -S . -B build/reader -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DDESFIRE_CXX_STANDARD=23 \
  -DDESFIRE_BUILD_PCSC=ON
cmake --build build/reader --parallel
cmake --install build/reader --prefix "$PWD/build/install"

cmake -S /path/to/consumer -B /path/to/consumer/build -G Ninja \
  -DCMAKE_PREFIX_PATH="$PWD/build/install"
cmake --build /path/to/consumer/build --parallel
```

PC/SC discovery and compilation do not prove compatibility with a particular reader, antenna,
firmware, card profile, or RF timing. Portable `SCardTransmit` also cannot guarantee interruption
of a blocked driver call; the PC/SC adapter documents that limitation through its capabilities.

## Adapt an existing reader

`CallbackTransport` accepts closures around an already open vendor connection. Declare limits
from the active reader/card configuration rather than inferring them from a model name:

```cpp
using namespace desfire;
using namespace desfire::transports;

TransportCapabilities limits{
    .framing = Framing::iso7816,
    .max_transmit = 261,
    .max_receive = 4096,
    .max_native_frame = 256,
    .can_cancel = true,
    .can_reset = true,
};

TransportCallbacks callbacks{
    .exchange = [&](ByteView frame, const ExchangeOptions& options) -> Result<Bytes> {
        return reader.transceive_once(frame, options);
    },
    .cancel = [&] { reader.cancel_pending_io(); },
    .reset = [&]() -> Result<void> { return reader.reset_card(); },
};

auto transport = std::make_shared<CallbackTransport>(limits, std::move(callbacks));
```

The application-specific `transceive_once` must:

- send one supplied frame once and return the complete frame response;
- honor the remaining deadline as closely as the reader API permits;
- return `Outcome::unknown` when transmission may have begun but completion is unconfirmed;
- avoid reconnecting, resending, or changing cards inside the callback; and
- make cancellation safe to call concurrently with exchange.

For a direct-native reader, set `Framing::native`. For an APDU reader, set
`Framing::iso7816`; native operations then use the DESFire `90 INS` envelope. Actual ISO 7816
operations still use the separate checked or raw ISO path.

## Lifecycle and recovery

1. Discover and activate the card with the platform API.
2. Construct one transport with the exact framing, limits, and cancellation capabilities.
3. Construct either one managed Card or one raw channel over that transport.
4. Resolve keys, select the application, and authenticate with the explicit session profile.
5. Inspect the error code, device status, and delivery outcome for every operation.
6. If the outcome is unknown, stop mutation retries and reconcile application/card state.
7. Destroy or close the Card before releasing callback context or closing the physical reader.
8. After removal or external reset, advance the connection generation or create a fresh transport.

The full concurrency and close rules are in [transport lifecycle](architecture/transport-lifecycle.md).
Supported operations and current target evidence are in the
[implementation matrix](../spec/coverage.md).
