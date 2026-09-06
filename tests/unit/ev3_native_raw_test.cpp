/**
 * @file ev3_native_raw_test.cpp
 * @brief Deterministic native raw framing, channel, and AF-chain boundary tests.
 */
#include <desfire/ev3/model/version.hpp>
#include <desfire/ev3/native/raw/channel.hpp>
#include <desfire/ev3/native/raw/codec.hpp>
#include <desfire/transports/replay.hpp>

#include <cstdlib>
#include <deque>
#include <iostream>
#include <memory>
#include <string_view>

namespace {

    using namespace desfire;
    using namespace desfire::ev3;
    using namespace desfire::ev3::model;
    using namespace desfire::transports;

    /**
     * @brief Terminate the test when a required invariant is false.
     * @param condition Observed condition.
     * @param message Stable assertion description.
     * @return Nothing; failure exits the process.
     */
    void expect(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(EXIT_FAILURE);
        }
    }

    /**
     * @brief Decode non-secret test fixture text.
     * @param text Even-length hexadecimal literal.
     * @return Owned bytes after fixture validation.
     */
    Bytes hex(std::string_view text) {
        auto decoded = from_hex(text);
        expect(static_cast<bool>(decoded), "fixture must be hexadecimal");
        return std::move(decoded.value());
    }

    /**
     * @brief Verify native and wrapped proprietary command framing exactly once.
     * @return Nothing; failure ends the process.
     */
    void check_framing() {
        auto native = native::raw::encode(0x60, {}, native::Framing::direct);
        expect(native && native.value() == hex("60"), "native GetVersion frame");
        auto wrapped = native::raw::encode(0x71, hex("0000"), native::Framing::iso_wrapped);
        expect(wrapped && wrapped.value() == hex("9071000002000000"),
               "wrapped authentication frame");
        auto parsed_native = native::raw::decode(hex("af0102"), native::Framing::direct);
        expect(parsed_native && parsed_native.value() == native::raw::Response{0xAF, hex("0102")},
               "native response status precedes payload");
        auto parsed_wrapped = native::raw::decode(hex("01029100"), native::Framing::iso_wrapped);
        expect(parsed_wrapped && parsed_wrapped.value() == native::raw::Response{0x00, hex("0102")},
               "wrapped response contains 91xx status");
    }

    /**
     * @brief Verify fixed GetVersion layout is decoded only from a complete payload.
     * @return Nothing; failure ends the process.
     */
    void check_version_layout() {
        auto version =
            parse_version(hex("04010112001805040102030405070401020304050601020304050124"));
        expect(version && version.value().hardware.vendor == 0x04 &&
                   version.value().software.protocol == 0x07 &&
                   version.value().uid ==
                       std::array<Byte, 7>{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
               "GetVersion fixed fields preserve wire order");
        auto truncated = parse_version(hex("0401"));
        expect(!truncated && truncated.error().code == ErrorCode::malformed_response,
               "truncated GetVersion is rejected");
    }

    /**
     * @brief Verify long EV3 response collection uses empty AF requests after first data frame.
     * @return Nothing; failure ends the process.
     */
    void check_response_chaining() {
        TransportCapabilities capabilities{};
        capabilities.framing = desfire::Framing::native;
        capabilities.max_transmit = 12;
        capabilities.max_native_frame = 12;
        auto transport = std::make_shared<ReplayTransport>(
            std::deque<ReplayStep>{{hex("60"), hex("af010203")}, {hex("af"), hex("000405")}},
            capabilities);
        auto channel = native::raw::RawNativeChannel::connect(transport).value();
        auto response =
            channel->exchange(native::raw::Request{.command = 0x60, .maximum_response = 32});
        expect(response && response.value() == native::raw::Response{0x00, hex("0102030405")},
               "AF response fragments are concatenated in order");
        expect(transport->remaining() == 0, "response chain consumes only expected frames");
    }

    /**
     * @brief Verify an upload interruption cannot be reported as a safe unsent mutation.
     * @return Nothing; failure ends the process.
     */
    void check_upload_uncertainty() {
        TransportCapabilities capabilities{};
        capabilities.framing = desfire::Framing::native;
        capabilities.max_transmit = 5;
        capabilities.max_native_frame = 5;
        auto transport = std::make_shared<ReplayTransport>(
            std::deque<ReplayStep>{{hex("3d01020304"), hex("af")},
                                   {hex("af0506"), Error{ErrorCode::timeout, "fixture interruption",
                                                         Outcome::not_sent}}},
            capabilities);
        auto channel = native::raw::RawNativeChannel::connect(transport).value();
        auto result = channel->exchange(native::raw::Request{
            .command = 0x3D, .data = hex("010203040506"), .maximum_response = 32});
        expect(!result && result.error().code == ErrorCode::timeout &&
                   result.error().outcome == Outcome::unknown,
               "partial upload retains unknown logical command outcome");
        expect(transport->remaining() == 0, "interrupted upload is not retried");
    }

    /** @brief Enforce a command-defined first AF boundary even when the transport can send more. */
    void check_semantic_upload_boundary() {
        TransportCapabilities capabilities{};
        capabilities.framing = desfire::Framing::native;
        capabilities.max_transmit = 64;
        capabilities.max_native_frame = 64;
        auto transport = std::make_shared<ReplayTransport>(
            std::deque<ReplayStep>{{hex("c901020304"), hex("af")},
                                   {hex("af05060708090a0b0c"), hex("00")}},
            capabilities);
        auto channel = native::raw::RawNativeChannel::connect(transport).value();
        auto result = channel->exchange(native::raw::Request{
            .command = 0xC9,
            .data = hex("0102030405060708090a0b0c"),
            .maximum_response = 32,
            .first_frame_data_size = 4,
        });
        expect(result && result.value() == native::raw::Response{0x00, {}},
               "semantic boundary sends the initial command and continuation exactly once");
        expect(transport->remaining() == 0, "semantic split consumes only its two expected frames");

        auto idle_transport =
            std::make_shared<ReplayTransport>(std::deque<ReplayStep>{}, capabilities);
        auto idle = native::raw::RawNativeChannel::connect(idle_transport).value();
        expect(!idle->exchange(native::raw::Request{.command = 0xC9,
                                                    .data = hex("0102"),
                                                    .maximum_response = 32,
                                                    .first_frame_data_size = 0}),
               "zero semantic frame size rejected before I/O");
        expect(!idle->exchange(native::raw::Request{.command = 0xC9,
                                                    .data = hex("0102"),
                                                    .maximum_response = 32,
                                                    .first_frame_data_size = 2}),
               "a semantic boundary must leave continuation data");
        expect(idle_transport->remaining() == 0,
               "invalid semantic boundaries perform no replay exchange");

        TransportCapabilities constrained = capabilities;
        constrained.max_transmit = 8;
        constrained.max_native_frame = 8;
        auto constrained_transport =
            std::make_shared<ReplayTransport>(std::deque<ReplayStep>{}, constrained);
        auto too_small = native::raw::RawNativeChannel::connect(constrained_transport).value();
        auto rejected = too_small->exchange(native::raw::Request{
            .command = 0xC9,
            .data = hex("0102030405060708090a0b0c"),
            .maximum_response = 32,
            .first_frame_data_size = 4,
            .single_continuation_frame = true,
        });
        expect(!rejected && rejected.error().code == ErrorCode::invalid_argument &&
                   rejected.error().outcome == Outcome::not_sent,
               "a mandatory single continuation is rejected before partial transmission");
    }

} // namespace

/**
 * @brief Run native raw codec, channel, and version-model unit checks.
 * @return Process status after all assertions pass.
 */
int main() {
    check_framing();
    check_version_layout();
    check_response_chaining();
    check_upload_uncertainty();
    check_semantic_upload_boundary();
    std::cout << "EV3 native raw tests passed.\n";
    return EXIT_SUCCESS;
}
