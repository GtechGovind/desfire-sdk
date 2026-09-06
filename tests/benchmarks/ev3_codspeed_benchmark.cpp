/**
 * @file ev3_codspeed_benchmark.cpp
 * @brief CodSpeed Google Benchmark coverage for native codecs and EV2 secure messaging.
 *
 * The workloads use fixed public values and perform no card, reader, network, or secret-provider
 * I/O. The separate threshold-capable host benchmark remains the deterministic local release gate.
 */
#include <benchmark/benchmark.h>

#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/native/raw/codec.hpp>
#include <desfire/ev3/security/ev2/session.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

/** @brief Extract the eight transmitted EV2 MAC bytes from a full AES-CMAC. */
static desfire::Bytes truncate_ev2_mac(desfire::ByteView full_mac) {
    desfire::Bytes transmitted_mac;
    transmitted_mac.reserve(8);
    for (std::size_t index = 1; index < 16; index += 2) {
        transmitted_mac.push_back(full_mac[index]);
    }
    return transmitted_mac;
}

/** @brief Construct a fresh EV2 session with fixed public benchmark keys. */
static desfire::Result<std::unique_ptr<desfire::ev3::security::ev2::Session>>
create_ev2_session(const std::shared_ptr<desfire::CryptoProvider>& crypto,
                   desfire::ByteView encryption_key, desfire::ByteView mac_key) {
    desfire::ev3::model::AuthenticationInfo information{};
    information.transaction_identifier = {0x01, 0x02, 0x03, 0x04};
    desfire::ev3::security::ev2::AuthenticationMaterial material{
        desfire::SecureBuffer(encryption_key), desfire::SecureBuffer(mac_key), information};
    return desfire::ev3::security::ev2::Session::create(crypto, std::move(material));
}

/** @brief Measure direct and ISO-wrapped native frame encoding and decoding. */
static void BM_Ev3NativeCodec(benchmark::State& state) {
    const desfire::Bytes payload(240, 0xA5);
    desfire::Bytes direct_response{0x00};
    desfire::append(direct_response, payload);
    desfire::Bytes wrapped_response(payload);
    desfire::append(wrapped_response, desfire::Bytes{0x91, 0x00});

    std::int64_t bytes_per_iteration{};
    for (auto iteration : state) {
        (void)iteration;
        auto direct = desfire::ev3::native::raw::encode_direct(0x3D, payload);
        auto wrapped = desfire::ev3::native::raw::encode_iso_wrapped(0x3D, payload);
        auto decoded_direct = desfire::ev3::native::raw::decode_direct(direct_response);
        auto decoded_wrapped = desfire::ev3::native::raw::decode_iso_wrapped(wrapped_response);
        if (!direct || !wrapped || !decoded_direct || !decoded_wrapped) {
            state.SkipWithError("native codec rejected a fixed valid benchmark frame");
            return;
        }
        bytes_per_iteration = static_cast<std::int64_t>(
            direct.value().size() + wrapped.value().size() + decoded_direct.value().data.size() +
            decoded_wrapped.value().data.size());
        benchmark::DoNotOptimize(direct.value().data());
        benchmark::DoNotOptimize(wrapped.value().data());
        benchmark::DoNotOptimize(decoded_direct.value().data.data());
        benchmark::DoNotOptimize(decoded_wrapped.value().data.data());
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(state.iterations() * bytes_per_iteration);
}

/** @brief Measure complete EV2 MAC command preparation and response verification. */
static void BM_Ev2MacRoundTrip(benchmark::State& state) {
    auto crypto_result = desfire::openssl_provider();
    if (!crypto_result) {
        state.SkipWithError("OpenSSL provider creation failed");
        return;
    }
    auto crypto = std::move(crypto_result.value());
    const desfire::Bytes encryption_key(16, 0x11);
    const desfire::Bytes mac_key(16, 0x22);
    auto session_result = create_ev2_session(crypto, encryption_key, mac_key);
    if (!session_result) {
        state.SkipWithError("EV2 session creation failed");
        return;
    }
    auto session = std::move(session_result.value());
    const desfire::Bytes header{0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00};
    const desfire::Bytes command_data(32, 0x5A);
    const desfire::Bytes response_data(32, 0xC3);

    for (auto iteration : state) {
        (void)iteration;
        if (session->command_counter() >= 60000) {
            session_result = create_ev2_session(crypto, encryption_key, mac_key);
            if (!session_result) {
                state.SkipWithError("EV2 session renewal failed");
                return;
            }
            session = std::move(session_result.value());
        }

        auto command = session->prepare_mac(0x3D, header, command_data);
        if (!command) {
            state.SkipWithError("EV2 command protection failed");
            return;
        }
        const std::uint16_t counter = session->command_counter();
        desfire::Bytes mac_input{0x00,
                                 static_cast<desfire::Byte>(counter),
                                 static_cast<desfire::Byte>(counter >> 8U),
                                 0x01,
                                 0x02,
                                 0x03,
                                 0x04};
        desfire::append(mac_input, response_data);
        auto full_mac = crypto->cmac(desfire::Cipher::aes128, mac_key, mac_input);
        if (!full_mac || full_mac.value().size() != 16) {
            state.SkipWithError("EV2 response MAC creation failed");
            return;
        }
        desfire::Bytes response(response_data);
        desfire::append(response, truncate_ev2_mac(full_mac.value()));
        auto verified = session->verify_response({0x00, std::move(response)});
        if (!verified || verified.value().size() != response_data.size()) {
            state.SkipWithError("EV2 response verification failed");
            return;
        }
        benchmark::DoNotOptimize(command.value().data());
        benchmark::DoNotOptimize(verified.value().data());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_Ev3NativeCodec);
BENCHMARK(BM_Ev2MacRoundTrip);
BENCHMARK_MAIN();
