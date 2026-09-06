/**
 * @file ev3_codec_session_benchmark.cpp
 * @brief Repeatable host benchmark for native codecs and EV2 MAC-session operations.
 *
 * The executable reports measurements for the current host. It asserts no product baseline unless
 * the caller explicitly supplies minimum thresholds.
 */
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/native/raw/codec.hpp>
#include <desfire/ev3/security/ev2/session.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string_view>

namespace {
    using namespace desfire;
    using namespace desfire::ev3;

    namespace ev2 = desfire::ev3::security::ev2;
    namespace raw = desfire::ev3::native::raw;

    /** @brief Parsed benchmark controls with thresholds disabled by default. */
    struct Options final {
        std::uint32_t iterations{20000};
        std::optional<double> minimum_codec_mib_per_second;
        std::optional<double> minimum_session_operations_per_second;
    };

    /** @brief Print supported benchmark controls without asserting a baseline. */
    void usage() {
        std::cout << "Usage: ev3_codec_session_benchmark [--iterations 1..60000] "
                     "[--min-codec-mib-s VALUE] [--min-session-ops-s VALUE]\n";
    }

    /** @brief Parse one positive integer without locale-dependent conversion. */
    std::optional<std::uint32_t> positive_integer(std::string_view text) {
        std::uint32_t value{};
        const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
        if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value == 0) {
            return {};
        }
        return value;
    }

    /** @brief Parse one finite nonnegative threshold without accepting trailing bytes. */
    std::optional<double> nonnegative_number(std::string_view text) {
        double value{};
        const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
        if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value < 0 ||
            !std::isfinite(value)) {
            return {};
        }
        return value;
    }

    /** @brief Parse benchmark controls and reject counter-exhausting iteration counts. */
    std::optional<Options> parse_options(int argc, char** argv) {
        Options options;
        for (int index = 1; index < argc; ++index) {
            const std::string_view argument(argv[index]);
            if (argument == "--help") {
                usage();
                std::exit(EXIT_SUCCESS);
            }
            if (index + 1 >= argc) {
                return {};
            }
            const std::string_view value(argv[++index]);
            if (argument == "--iterations") {
                auto parsed = positive_integer(value);
                if (!parsed || *parsed > 60000) {
                    return {};
                }
                options.iterations = *parsed;
            } else if (argument == "--min-codec-mib-s") {
                auto parsed = nonnegative_number(value);
                if (!parsed) {
                    return {};
                }
                options.minimum_codec_mib_per_second = *parsed;
            } else if (argument == "--min-session-ops-s") {
                auto parsed = nonnegative_number(value);
                if (!parsed) {
                    return {};
                }
                options.minimum_session_operations_per_second = *parsed;
            } else {
                return {};
            }
        }
        return options;
    }

    /** @brief Return elapsed wall-clock seconds with a nonzero denominator. */
    double elapsed_seconds(std::chrono::steady_clock::time_point start) {
        const auto elapsed = std::chrono::steady_clock::now() - start;
        return std::max(std::chrono::duration<double>(elapsed).count(), 1e-9);
    }

    /** @brief Extract the EV2 transmitted MAC bytes from one full AES-CMAC result. */
    Bytes truncate_ev2_mac(ByteView full) {
        Bytes output;
        output.reserve(8);
        for (std::size_t index = 1; index < 16; index += 2) {
            output.push_back(full[index]);
        }
        return output;
    }

    /** @brief Benchmark direct/wrapped encoding and decoding using fixed-size public data. */
    double benchmark_codec(std::uint32_t iterations, std::uint64_t& observed_bytes) {
        const Bytes payload(240, 0xA5);
        Bytes direct_response{0x00};
        append(direct_response, payload);
        Bytes wrapped_response(payload);
        append(wrapped_response, Bytes{0x91, 0x00});
        observed_bytes = 0;
        const auto start = std::chrono::steady_clock::now();
        for (std::uint32_t iteration = 0; iteration < iterations; ++iteration) {
            auto direct = raw::encode_direct(0x3D, payload);
            auto wrapped = raw::encode_iso_wrapped(0x3D, payload);
            auto decoded_direct = raw::decode_direct(direct_response);
            auto decoded_wrapped = raw::decode_iso_wrapped(wrapped_response);
            if (!direct || !wrapped || !decoded_direct || !decoded_wrapped) {
                return 0;
            }
            observed_bytes += direct.value().size() + wrapped.value().size() +
                              decoded_direct.value().data.size() +
                              decoded_wrapped.value().data.size();
        }
        return static_cast<double>(observed_bytes) / (1024.0 * 1024.0) / elapsed_seconds(start);
    }

    /** @brief Benchmark one EV2 MAC command/verified-response state transition per iteration. */
    double benchmark_session(std::uint32_t iterations, std::uint64_t& observed_operations) {
        auto crypto_result = desfire::openssl_provider();
        if (!crypto_result) {
            return 0;
        }
        auto crypto = std::move(crypto_result.value());
        const Bytes encryption_key(16, 0x11);
        const Bytes mac_key(16, 0x22);
        model::AuthenticationInfo information{};
        information.transaction_identifier = {0x01, 0x02, 0x03, 0x04};
        ev2::AuthenticationMaterial material{SecureBuffer(encryption_key), SecureBuffer(mac_key),
                                             information};
        auto session_result = ev2::Session::create(crypto, std::move(material));
        if (!session_result) {
            return 0;
        }
        auto session = std::move(session_result.value());
        const Bytes header{0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00};
        const Bytes command_data(32, 0x5A);
        const Bytes response_data(32, 0xC3);
        observed_operations = 0;
        const auto start = std::chrono::steady_clock::now();
        for (std::uint32_t iteration = 0; iteration < iterations; ++iteration) {
            auto command = session->prepare_mac(0x3D, header, command_data);
            if (!command) {
                return 0;
            }
            const std::uint16_t counter = session->command_counter();
            Bytes mac_input{0x00,
                            static_cast<Byte>(counter),
                            static_cast<Byte>(counter >> 8U),
                            0x01,
                            0x02,
                            0x03,
                            0x04};
            append(mac_input, response_data);
            auto full_mac = crypto->cmac(Cipher::aes128, mac_key, mac_input);
            if (!full_mac || full_mac.value().size() != 16) {
                return 0;
            }
            Bytes response(response_data);
            append(response, truncate_ev2_mac(full_mac.value()));
            auto verified = session->verify_response({0x00, std::move(response)});
            if (!verified || verified.value().size() != response_data.size()) {
                return 0;
            }
            ++observed_operations;
        }
        return static_cast<double>(observed_operations) / elapsed_seconds(start);
    }

} // namespace

/** @brief Run repeatable host measurements and apply only caller-supplied thresholds. */
int main(int argc, char** argv) {
    const auto options = parse_options(argc, argv);
    if (!options) {
        usage();
        return 2;
    }

    std::uint64_t codec_bytes{};
    std::uint64_t session_operations{};
    const double codec_rate = benchmark_codec(options->iterations, codec_bytes);
    const double session_rate = benchmark_session(options->iterations, session_operations);
    if (codec_rate <= 0 || session_rate <= 0) {
        std::cerr << "Benchmark operation failed\n";
        return 1;
    }

    std::cout << "iterations=" << options->iterations << " codec_bytes=" << codec_bytes
              << " codec_mib_per_second=" << codec_rate
              << " session_operations=" << session_operations
              << " session_operations_per_second=" << session_rate << '\n';
    std::cout << "Measurements are host-local; no baseline is asserted without an explicit "
                 "minimum threshold.\n";

    bool accepted = true;
    if (options->minimum_codec_mib_per_second) {
        accepted = accepted && codec_rate >= *options->minimum_codec_mib_per_second;
    }
    if (options->minimum_session_operations_per_second) {
        accepted = accepted && session_rate >= *options->minimum_session_operations_per_second;
    }
    if (!accepted) {
        std::cerr << "One or more caller-supplied throughput thresholds were not met\n";
        return 3;
    }
    return 0;
}
