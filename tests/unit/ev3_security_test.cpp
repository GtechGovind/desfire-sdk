/**
 * @file ev3_security_test.cpp
 * @brief AES session known-answer vectors and adversarial state-machine regression checks.
 *
 * Published numeric fixtures: NXP AN12343 rev 1.1 tables 16 and 23 through 26
 * (the shared EV2 AES construction, documented on DESFire Light), and AN10922
 * rev 2.2 table 2. These host checks do not claim EV3 hardware qualification.
 */
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/security/ev2/authentication.hpp>
#include <desfire/ev3/security/ev2/session.hpp>
#include <desfire/ev3/security/key_derivation/aes128.hpp>
#include <desfire/ev3/security/key_derivation/nxp_aes128.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace {
    using namespace desfire;
    using namespace desfire::ev3;
    using namespace desfire::ev3::security::ev2;

    namespace key_derivation = desfire::ev3::security::key_derivation;
    namespace nxp_aes128 = desfire::ev3::security::key_derivation::nxp_aes128;

    /** @brief Stop the executable with a stable assertion message when an invariant fails. */
    void expect(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(EXIT_FAILURE);
        }
    }

    /** @brief Decode an independently specified, non-secret hexadecimal fixture. */
    Bytes hex(std::string_view text) {
        auto value = from_hex(text);
        expect(static_cast<bool>(value), "valid hexadecimal test fixture");
        return std::move(value.value());
    }

    /** @brief Fault-injection wrapper; deterministic random is restricted to this test. */
    class TestCrypto final : public CryptoProvider {
    public:

        /** @brief Retain the real provider used for all non-injected primitive operations. */
        explicit TestCrypto(std::shared_ptr<CryptoProvider> base) : base_(std::move(base)) {}

        Bytes nonce = hex("B04D0787C93EE0CC8CACC8E86F16C6FE");
        bool fail_random{};
        bool short_cmac{};
        bool fail_cmac{};
        bool short_cbc{};
        bool throw_cbc{};
        std::size_t random_calls{};
        std::size_t decryptions{};
        std::size_t encryptions{};

        /** @brief Return the deterministic test nonce or the configured local failure. */
        Result<Bytes> random(std::size_t) override {
            ++random_calls;
            if (fail_random) {
                return Error{ErrorCode::crypto, "injected random failure"};
            }
            return nonce;
        }

        /** @brief Count primitive directions and inject malformed output or an exception. */
        Result<Bytes> cbc(Cipher cipher, ByteView key, ByteView iv, ByteView input,
                          bool encrypt) override {
            if (encrypt) {
                ++encryptions;
            } else {
                ++decryptions;
            }
            if (throw_cbc) {
                throw std::runtime_error("injected provider failure");
            }
            if (short_cbc) {
                return Bytes(15);
            }
            return base_->cbc(cipher, key, iv, input, encrypt);
        }

        /** @brief Calculate a full real CMAC or return the configured provider fault. */
        Result<Bytes> cmac(Cipher cipher, ByteView key, ByteView input) override {
            if (short_cmac) {
                return Bytes(15);
            }
            if (fail_cmac) {
                return Error{ErrorCode::crypto, "injected CMAC failure"};
            }
            return base_->cmac(cipher, key, input);
        }

        /** @brief Preserve the provider contract for the unused ECDSA primitive. */
        Result<bool> verify_ecdsa(std::string_view curve, ByteView key, ByteView digest,
                                  ByteView signature) override {
            return base_->verify_ecdsa(curve, key, digest, signature);
        }

    private:

        std::shared_ptr<CryptoProvider> base_;
    };

    /** @brief Create independently specified session keys and public transaction metadata. */
    AuthenticationMaterial material(std::string_view enc, std::string_view mac,
                                    std::string_view ti) {
        AuthenticationMaterial output{SecureBuffer(hex(enc)), SecureBuffer(hex(mac)), {}};
        std::ranges::copy(hex(ti), output.information.transaction_identifier.begin());
        return output;
    }

    /** @brief Create the AN12343 Full-mode fixture at a caller-selected command counter. */
    std::unique_ptr<Session> full_session(std::shared_ptr<CryptoProvider> crypto,
                                          std::uint16_t counter = 0) {
        auto result = Session::create(std::move(crypto),
                                      material("FFBCFE1F41840A09C9A88D0A4B10DF05",
                                               "37E7234B11BEBEFDE41A8F290090EF80", "CD73D8E5"),
                                      counter);
        expect(static_cast<bool>(result), "create fixture secure session");
        return std::move(result.value());
    }

    /** @brief Return the complete published table-26 ciphertext and truncated response CMAC. */
    Bytes full_response_vector() {
        return hex("8848D0F9B9FD4495770C89925B2A85C7"
                   "274D350FA9029C484D43804886662DC4"
                   "2D7F40A6D7A415E4A71EFF79EB8E5721"
                   "AC3BF1CAAFE8EB2CAA2DC162E67A97A3"
                   "8ED7888F22B3A587");
    }

    /** @brief Build adversarial authenticated ciphertext using primitives outside the EV2 session.
     */
    Bytes sign_response(CryptoProvider& crypto, ByteView ciphertext, std::uint16_t counter) {
        Bytes input{0x00, static_cast<Byte>(counter), static_cast<Byte>(counter >> 8U)};
        append(input, hex("CD73D8E5"));
        append(input, ciphertext);
        auto mac = crypto.cmac(Cipher::aes128, hex("37E7234B11BEBEFDE41A8F290090EF80"), input);
        expect(static_cast<bool>(mac), "fixture MAC computation");
        Bytes output(ciphertext.begin(), ciphertext.end());
        for (std::size_t index = 1; index < 16; index += 2) {
            output.push_back(mac.value()[index]);
        }
        return output;
    }

    /** @brief Encrypt adversarial padded data with the fixture's independently specified response
     * IV. */
    Bytes encrypt_fixture(CryptoProvider& crypto, ByteView plaintext) {
        const auto zero = Bytes(16);
        const auto key = hex("FFBCFE1F41840A09C9A88D0A4B10DF05");
        auto iv =
            crypto.cbc(Cipher::aes128, key, zero, hex("5AA5CD73D8E502000000000000000000"), true);
        expect(static_cast<bool>(iv), "fixture IV encryption");
        auto ciphertext = crypto.cbc(Cipher::aes128, key, iv.value(), plaintext, true);
        expect(static_cast<bool>(ciphertext), "fixture ciphertext encryption");
        return std::move(ciphertext.value());
    }

    /** @brief Verify published First keys, NonFirst continuity, bad proofs, and pre-I/O failures.
     */
    void authentication_vectors(std::shared_ptr<CryptoProvider> base) {
        TestCrypto crypto(base);
        std::size_t frames{};
        auto exchange = [&](Byte command, ByteView payload) -> Result<native::raw::Response> {
            ++frames;
            if (frames == 1) {
                expect(command == 0x71 && constant_time_equal(payload, hex("0000")),
                       "First command and LenCap match published vector");
                return native::raw::Response{0xAF, hex("24677DDBD46349E623798FD729006E79")};
            }
            expect(frames == 2 && command == 0xAF &&
                       constant_time_equal(payload, hex("3B50445F21D21D77D500794DEB245E5A"
                                                        "754F5F901844259F4C9B31A5C7335ACD")),
                   "First reciprocal challenge matches published ciphertext");
            return native::raw::Response{0x00, hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2"
                                                   "B4B074F638EEF7FFF9254963B65C7759")};
        };
        auto result = authenticate_first(crypto, 0, Bytes(16), exchange);
        expect(result && frames == 2 &&
                   constant_time_equal(result.value().encryption_key.view(),
                                       hex("63DC07286289A7A6C0334CA31C314A04")) &&
                   constant_time_equal(result.value().mac_key.view(),
                                       hex("774F26743ECE6AF5033B6AE8522946F6")) &&
                   result.value().information.transaction_identifier ==
                       std::array<Byte, 4>{0x8C, 0xF1, 0x41, 0xF3},
               "AN12343 table 16 First mutual authentication and both session keys");

        const auto previous = result.value().information;
        frames = 0;
        auto nonfirst_exchange = [&](Byte command,
                                     ByteView payload) -> Result<native::raw::Response> {
            if (++frames == 1) {
                expect(command == 0x77 && constant_time_equal(payload, hex("01")),
                       "NonFirst carries exactly its key selector");
                return native::raw::Response{0xAF, hex("24677DDBD46349E623798FD729006E79")};
            }
            expect(command == 0xAF, "NonFirst reciprocal challenge frame");
            auto final = base->cbc(Cipher::aes128, Bytes(16), Bytes(16),
                                   hex("4D0787C93EE0CC8CACC8E86F16C6FEB0"), true);
            expect(static_cast<bool>(final), "fixture NonFirst proof");
            return native::raw::Response{0x00, std::move(final.value())};
        };
        auto nonfirst = authenticate_nonfirst(crypto, 1, Bytes(16), previous, nonfirst_exchange);
        expect(nonfirst && nonfirst.value().information == previous && frames == 2 &&
                   constant_time_equal(nonfirst.value().encryption_key.view(),
                                       hex("63DC07286289A7A6C0334CA31C314A04")),
               "NonFirst verifies rotated nonce and preserves metadata");
        auto continued = Session::create(base, std::move(nonfirst.value()), 1234);
        expect(continued && continued.value()->command_counter() == 1234,
               "replacement keys retain the supplied NonFirst counter");

        for (const auto mutation : {0, 1}) {
            frames = 0;
            auto bad_proof = [&](Byte, ByteView) -> Result<native::raw::Response> {
                if (++frames == 1) {
                    return native::raw::Response{0xAF, hex("24677DDBD46349E623798FD729006E79")};
                }
                auto clear =
                    hex("8CF141F34D0787C93EE0CC8CACC8E86F16C6FEB0000000000000000000000000");
                if (mutation == 0) {
                    clear[4] ^= 1;
                } else {
                    clear[26] ^= 1;
                }
                auto encrypted = base->cbc(Cipher::aes128, Bytes(16), Bytes(16), clear, true);
                expect(static_cast<bool>(encrypted), "invalid authentication proof fixture");
                return native::raw::Response{0x00, std::move(encrypted.value())};
            };
            auto failure = authenticate_first(crypto, 0, Bytes(16), bad_proof);
            expect(!failure && failure.error().code == ErrorCode::authentication &&
                       failure.error().outcome == Outcome::unknown,
                   "wrong nonce or capability echo never establishes keys");
        }

        frames = 0;
        crypto.nonce.resize(15);
        auto short_random = authenticate_first(crypto, 0, Bytes(16), exchange);
        expect(!short_random && short_random.error().code == ErrorCode::crypto && frames == 0,
               "short random output fails before card I/O");
        crypto.nonce.resize(16);
        crypto.fail_random = true;
        auto no_random = authenticate_first(crypto, 0, Bytes(16), exchange);
        expect(!no_random && frames == 0 && no_random.error().outcome == Outcome::not_sent,
               "random-source failure never starts authentication");
        crypto.fail_random = false;
        auto invalid_key = authenticate_first(crypto, 64, Bytes(16), exchange);
        expect(!invalid_key && frames == 0, "invalid key selector fails before card I/O");

        auto malformed = authenticate_first(crypto, 0, Bytes(16),
                                            [](Byte, ByteView) -> Result<native::raw::Response> {
                                                return native::raw::Response{0xAF, Bytes(15)};
                                            });
        expect(!malformed && malformed.error().code == ErrorCode::malformed_response,
               "truncated encrypted card nonce rejected");
        auto exception = authenticate_first(crypto, 0, Bytes(16),
                                            [](Byte, ByteView) -> Result<native::raw::Response> {
                                                throw std::runtime_error("test");
                                            });
        expect(!exception && exception.error().outcome == Outcome::unknown,
               "dependency exceptions preserve authentication uncertainty");
    }

    /** @brief Verify variable PCD capability requests, padded echoes, bounds, and provider faults.
     */
    void authentication_capabilities(const std::shared_ptr<CryptoProvider>& base) {
        TestCrypto crypto(base);
        const auto encrypted_random_b = hex("24677DDBD46349E623798FD729006E79");
        const auto encrypted_reader_proof =
            hex("3B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD");

        std::size_t frames{};
        auto short_capability_exchange = [&](Byte command,
                                             ByteView payload) -> Result<native::raw::Response> {
            if (++frames == 1) {
                expect(command == 0x71 && constant_time_equal(payload, hex("0003A1A2A3")),
                       "First request encodes key, length, and three PCD capability bytes");
                return native::raw::Response{0xAF, encrypted_random_b};
            }
            expect(frames == 2 && command == 0xAF &&
                       constant_time_equal(payload, encrypted_reader_proof),
                   "PCD capabilities do not alter the reciprocal nonce proof");
            return native::raw::Response{
                0x00, hex("04C6DBD67417ED0D31DDDE4D2E3FFAC275944C9B56DE150BA3BD15563236A380")};
        };
        auto short_capabilities =
            authenticate_first(crypto, 0, Bytes(16), hex("A1A2A3"), short_capability_exchange);
        expect(short_capabilities && frames == 2 &&
                   short_capabilities.value().information.picc_capabilities ==
                       std::array<Byte, 6>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66} &&
                   short_capabilities.value().information.pcd_capabilities ==
                       std::array<Byte, 6>{0xA1, 0xA2, 0xA3, 0x00, 0x00, 0x00},
               "First returns PICC capabilities and the verified six-byte padded PCD echo");

        frames = 0;
        auto maximum_capability_exchange = [&](Byte command,
                                               ByteView payload) -> Result<native::raw::Response> {
            if (++frames == 1) {
                expect(command == 0x71 && constant_time_equal(payload, hex("0006010203040506")),
                       "six-byte PCD capability boundary is encoded without truncation");
                return native::raw::Response{0xAF, encrypted_random_b};
            }
            expect(command == 0xAF && constant_time_equal(payload, encrypted_reader_proof),
                   "maximum PCD capability request completes the nonce proof");
            return native::raw::Response{
                0x00, hex("04C6DBD67417ED0D31DDDE4D2E3FFAC24F1764E25280F70D6BEC7DE152B87114")};
        };
        auto maximum_capabilities = authenticate_first(crypto, 0, Bytes(16), hex("010203040506"),
                                                       maximum_capability_exchange);
        expect(maximum_capabilities && frames == 2 &&
                   maximum_capabilities.value().information.pcd_capabilities ==
                       std::array<Byte, 6>{1, 2, 3, 4, 5, 6},
               "six-byte PCD capability boundary authenticates successfully");

        const auto random_calls = crypto.random_calls;
        frames = 0;
        auto oversized =
            authenticate_first(crypto, 0, Bytes(16), Bytes(7), maximum_capability_exchange);
        expect(!oversized && oversized.error().code == ErrorCode::invalid_argument && frames == 0 &&
                   crypto.random_calls == random_calls,
               "seven PCD capability bytes fail before randomness or card I/O");

        const std::array<std::string_view, 2> tampered_echoes{
            "04C6DBD67417ED0D31DDDE4D2E3FFAC26CFB6517E02805D21A763B0C4DE57424",
            "04C6DBD67417ED0D31DDDE4D2E3FFAC2CCF6EB02D4B5136A8F492A376B6ABD7B"};
        for (const auto encrypted_echo : tampered_echoes) {
            frames = 0;
            auto tampered_exchange = [&](Byte, ByteView) -> Result<native::raw::Response> {
                if (++frames == 1) {
                    return native::raw::Response{0xAF, encrypted_random_b};
                }
                return native::raw::Response{0x00, hex(encrypted_echo)};
            };
            auto tampered =
                authenticate_first(crypto, 0, Bytes(16), hex("A1A2A3"), tampered_exchange);
            expect(!tampered && tampered.error().code == ErrorCode::authentication &&
                       tampered.error().outcome == Outcome::unknown,
                   "changed PCD capability value or zero-padding fails authentication");
        }

        frames = 0;
        crypto.fail_random = true;
        auto random_failure =
            authenticate_first(crypto, 0, Bytes(16), hex("A1A2A3"), short_capability_exchange);
        expect(!random_failure && random_failure.error().code == ErrorCode::crypto && frames == 0,
               "capability authentication preserves pre-I/O random provider failure");
        crypto.fail_random = false;

        frames = 0;
        crypto.fail_cmac = true;
        auto derivation_failure =
            authenticate_first(crypto, 0, Bytes(16), hex("A1A2A3"), short_capability_exchange);
        expect(!derivation_failure && derivation_failure.error().code == ErrorCode::crypto &&
                   derivation_failure.error().outcome == Outcome::unknown && frames == 2,
               "capability authentication preserves post-proof session-key provider failure");
    }

    /** @brief Verify published MAC and Full command/response pairs with exact wire bytes. */
    void messaging_vectors(std::shared_ptr<CryptoProvider> crypto) {
        auto mac_result =
            Session::create(crypto, material("C4C9F2A734F32967FAC80A0F37C764F0",
                                             "9366FA195EB566F5BD2BAD4020B83002", "E2D3AF69"));
        expect(static_cast<bool>(mac_result), "MAC vector session");
        auto& mac = *mac_result.value();
        auto command = mac.prepare_mac(0x8D, hex("00000000190000"), Bytes(25, 0x22));
        Bytes expected = hex("00000000190000");
        append(expected, Bytes(25, 0x22));
        append(expected, hex("68F2C28C575A1628"));
        expect(command && command.value() == expected && mac.command_counter() == 1,
               "AN12343 table 23 command CMAC and counter");
        auto response = mac.verify_response({0, hex("0820F68898C2A7F1")});
        expect(response && response.value().empty(), "AN12343 table 23 response CMAC");
        auto read = mac.prepare_mac(0xAD, hex("00000000300000"), {});
        expect(read && read.value() == hex("000000003000000D9BE191D5960834"),
               "AN12343 table 24 next command CMAC");
        Bytes clear(48);
        std::fill_n(clear.begin(), 25, 0x22);
        Bytes wire(clear);
        append(wire, hex("A49A44222D926666"));
        auto verified = mac.verify_response({0, wire});
        expect(verified && verified.value() == clear && mac.command_counter() == 2,
               "AN12343 table 24 response data is released after MAC verification");

        auto full = full_session(crypto);
        auto encrypted = full->prepare_full(0x8D, hex("00000000190000"), Bytes(25, 0x22));
        expect(encrypted &&
                   encrypted.value() == hex("00000000190000D7446FBC912580C0A65E738D28B609E4"
                                            "3ADBB8FB2B4CA68744D1BBEBB37EBD32700ADF7BB9F62A6C"),
               "AN12343 table 25 command encryption, padding, IV and CMAC");
        auto full_write = full->verify_and_decrypt_full_response({0, hex("B9A534A7A73EE0DD")}, 0);
        expect(full_write && full_write.value().empty(),
               "Full write accepts authenticated empty response");
        auto full_read = full->prepare_full(0xAD, hex("00000000300000"), {});
        expect(full_read && full_read.value() == hex("000000003000007CF94F122B3DB05F"),
               "AN12343 table 26 Full read adds no encrypted empty command block");
        auto decrypted = full->verify_and_decrypt_full_response({0, full_response_vector()}, 48);
        expect(decrypted && decrypted.value() == clear && full->command_counter() == 2,
               "AN12343 table 26 MAC, response IV, full padding block and exact plaintext");
    }

    /** @brief Assert fail-closed tampering, padding, length, and primitive-failure behavior. */
    void messaging_failures(std::shared_ptr<CryptoProvider> base) {
        auto crypto = std::make_shared<TestCrypto>(base);
        for (const auto position :
             {std::size_t{0}, std::size_t{63}, std::size_t{64}, std::size_t{71}}) {
            auto session = full_session(crypto, 1);
            expect(static_cast<bool>(session->prepare_full(0xAD, hex("00000000300000"), {})),
                   "prepare tampering fixture");
            auto wire = full_response_vector();
            wire[position] ^= 1;
            const auto before = crypto->decryptions;
            auto bad = session->verify_and_decrypt_full_response({0, wire});
            expect(!bad && bad.error().code == ErrorCode::integrity &&
                       bad.error().outcome == Outcome::unknown && crypto->decryptions == before,
                   "ciphertext or MAC tampering is rejected before decryption");
            auto reused = session->prepare_mac(0xAD, {}, {});
            expect(!reused && reused.error().code == ErrorCode::session_invalid,
                   "integrity failure permanently invalidates session");
        }

        for (const auto length : {std::size_t{47}, std::size_t{49}}) {
            auto session = full_session(base, 1);
            expect(static_cast<bool>(session->prepare_mac(0xAD, hex("00000000300000"), {})),
                   "prepare expected-length fixture");
            auto bad =
                session->verify_and_decrypt_full_response({0, full_response_vector()}, length);
            expect(!bad && bad.error().code == ErrorCode::integrity,
                   "authenticated unexpected plaintext length rejected");
        }

        for (const auto invalid_padding : {0, 1, 2}) {
            Bytes clear(invalid_padding == 2 ? 32 : 16);
            if (invalid_padding == 1) {
                clear.back() = 0x01;
            } else if (invalid_padding == 2) {
                clear.front() = 0x80; // Thirty-two padding bytes are noncanonical.
            }
            auto wire = sign_response(*base, encrypt_fixture(*base, clear), 2);
            auto session = full_session(base, 1);
            expect(static_cast<bool>(session->prepare_mac(0xAD, {}, {})),
                   "prepare padding fixture");
            auto bad = session->verify_and_decrypt_full_response({0, wire});
            expect(!bad && bad.error().code == ErrorCode::integrity,
                   "valid MAC cannot make malformed or overlong padding acceptable");
        }

        auto truncated = full_session(base, 1);
        expect(static_cast<bool>(truncated->prepare_mac(0xAD, {}, {})),
               "prepare truncation fixture");
        auto short_cipher =
            truncated->verify_and_decrypt_full_response({0, sign_response(*base, Bytes(15), 2)});
        expect(!short_cipher && short_cipher.error().code == ErrorCode::integrity,
               "authenticated non-block ciphertext rejected");

        auto empty = full_session(base, 1);
        expect(static_cast<bool>(empty->prepare_mac(0xAD, {}, {})), "prepare missing data fixture");
        auto missing = empty->verify_and_decrypt_full_response({0, sign_response(*base, {}, 2)}, 1);
        expect(!missing && missing.error().code == ErrorCode::integrity,
               "empty Full response cannot satisfy nonzero expected length");

        auto short_mac = full_session(base);
        expect(static_cast<bool>(short_mac->prepare_mac(0xAD, {}, {})),
               "prepare missing MAC fixture");
        expect(!short_mac->verify_response({0, Bytes(7)}), "truncated MAC rejected");

        auto failed_provider = full_session(crypto);
        expect(static_cast<bool>(failed_provider->prepare_mac(0xAD, {}, {})),
               "prepare provider failure fixture");
        crypto->fail_cmac = true;
        auto failure = failed_provider->verify_response({0, Bytes(8)});
        expect(!failure && failure.error().outcome == Outcome::unknown,
               "response crypto failure never claims the command was unsent");
        crypto->fail_cmac = false;
        crypto->short_cmac = true;
        auto malformed_provider = full_session(crypto);
        expect(!malformed_provider->prepare_mac(0xAD, {}, {}), "short provider CMAC rejected");
        crypto->short_cmac = false;
    }

    /** @brief Exercise Plain counter continuity, mode separation, response replay, and exhaustion.
     */
    void counter_and_plain(std::shared_ptr<CryptoProvider> crypto) {
        auto session = full_session(crypto);
        auto command = session->prepare_plain(0xAD, hex("00000000190000"), hex("0102"));
        expect(command && command.value() == hex("000000001900000102") &&
                   session->command_counter() == 1,
               "authenticated Plain command advances counter without adding MAC");
        expect(!session->prepare_mac(0xAD, {}, {}), "pending Plain response blocks next command");
        expect(!session->verify_response({0, Bytes(8)}),
               "Plain response cannot enter protected verifier");
        auto accepted = session->accept_plain_response({0, hex("80AA")});
        expect(accepted && accepted.value() == hex("80AA"),
               "Plain data accepted as unauthenticated bytes");
        auto next = session->prepare_mac(0xAD, hex("00000000300000"), {});
        expect(next && next.value() == hex("000000003000007CF94F122B3DB05F"),
               "next protected command uses counter advanced by Plain mode");
        expect(!session->accept_plain_response({0, {}}),
               "protected response cannot bypass MAC verification");
        expect(static_cast<bool>(session->verify_response({0, full_response_vector()})),
               "MAC verification remains possible after rejected API misuse");
        expect(!session->verify_response({0, full_response_vector()}),
               "duplicate response rejected");

        for (const auto mode : {0, 1, 2}) {
            auto exhausted = full_session(crypto, std::numeric_limits<std::uint16_t>::max());
            Result<Bytes> blocked = invalid("unselected test mode");
            if (mode == 0) {
                blocked = exhausted->prepare_plain(0xAD, {}, {});
            } else if (mode == 1) {
                blocked = exhausted->prepare_mac(0xAD, {}, {});
            } else {
                blocked = exhausted->prepare_full(0xAD, {}, Bytes(16));
            }
            expect(!blocked && blocked.error().code == ErrorCode::counter_exhausted,
                   "all communication modes reject counter wrap before I/O");
        }
        auto last = full_session(crypto, 0xFFFE);
        expect(static_cast<bool>(last->prepare_plain(0xAD, {}, {})),
               "last representable command permitted");
        expect(last->command_counter() == 0xFFFF &&
                   static_cast<bool>(last->accept_plain_response({0, {}})),
               "last response finishes at counter FFFF");
        expect(!last->prepare_plain(0xAD, {}, {}), "following command cannot wrap to zero");

        for (const auto status : {Byte{0xAF}, Byte{0x9D}}) {
            auto rejected = full_session(crypto);
            expect(static_cast<bool>(rejected->prepare_plain(0xAD, {}, {})),
                   "prepare terminal status fixture");
            expect(!rejected->accept_plain_response({status, {}}) &&
                       !rejected->prepare_plain(0xAD, {}, {}),
                   "nonterminal or error Plain response invalidates session");
        }
    }

    /** @brief Verify published diversification, short-context subtleties, and provider failures. */
    void diversification(std::shared_ptr<CryptoProvider> crypto) {
        const auto key_bytes = hex("00112233445566778899AABBCCDDEEFF");
        auto key = key_derivation::Aes128Key::import(key_bytes);
        expect(static_cast<bool>(key), "valid exact AES-128 master-key fixture");
        const auto make_context = [](ByteView input) {
            return key_derivation::Aes128DerivationContext::make(
                key_derivation::KeyPurpose::offline_operation,
                desfire::ev3::model::KeyNumber::make(0).value(), {}, {}, input);
        };
        auto context = make_context(hex("04782E21801D803042F54E585020416275"));
        expect(static_cast<bool>(context), "valid published diversification context");
        auto derived = nxp_aes128::derive(*crypto, key.value(), context.value());
        expect(derived && constant_time_equal(derived.value().view(),
                                              hex("A8DD63A3B89D54B37CA802473FDA9175")),
               "AN10922 table 2 published AES-128 key diversification vector");
        // Independent CLI AES-CBC fixtures use AN10922's published K1/K2 constants.
        const std::array<std::pair<std::size_t, std::string_view>, 5> cases{
            {{1, "281049D52ECBC8F60961993D34DE3D54"},
             {7, "E8B7F67C78C34AF1446E331EF7E6D3FF"},
             {15, "5A3C7F6F0687F24F82DEE7EDA0970D08"},
             {16, "FEED9FBD36CDB16819A72D30BCF9240B"},
             {31, "21C28CD89BB3147F66C7DBD4851CAB20"}}};
        for (const auto& [size, expected] : cases) {
            Bytes input(size);
            for (std::size_t index = 0; index < size; ++index) {
                input[index] = static_cast<Byte>(index);
            }
            auto input_context = make_context(input);
            expect(static_cast<bool>(input_context), "valid bounded diversification context");
            auto output = nxp_aes128::derive(*crypto, key.value(), input_context.value());
            expect(output && constant_time_equal(output.value().view(), hex(expected)),
                   "AN10922 short, boundary, and maximum input vectors");
            if (size <= 15) {
                Bytes ordinary{0x01};
                append(ordinary, input);
                auto cmac = crypto->cmac(Cipher::aes128, key.value().view(), ordinary);
                expect(cmac && !constant_time_equal(cmac.value(), output.value().view()),
                       "short AN10922 context does not collapse to ordinary one-block CMAC");
            }
        }
        auto empty_context = make_context({});
        auto oversized_context = make_context(Bytes(32));
        expect(empty_context && oversized_context &&
                   !nxp_aes128::derive(*crypto, key.value(), empty_context.value()) &&
                   !nxp_aes128::derive(*crypto, key.value(), oversized_context.value()) &&
                   !key_derivation::Aes128Key::import(Bytes(15)),
               "invalid diversification sizes fail locally");
        nxp_aes128::Deriver provider(crypto);
        auto adapted = provider.derive(key.value(), context.value());
        expect(adapted && constant_time_equal(adapted.value().view(), derived.value().view()),
               "Card derivation provider adapter returns the same protected key");
        nxp_aes128::Deriver missing(nullptr);
        expect(!missing.derive(key.value(), context.value()), "null primitive provider rejected");
        TestCrypto faults(crypto);
        faults.short_cbc = true;
        expect(!nxp_aes128::derive(faults, key.value(), context.value()),
               "short AES provider output rejected");
        faults.short_cbc = false;
        faults.throw_cbc = true;
        expect(!nxp_aes128::derive(faults, key.value(), context.value()),
               "diversification catches provider exceptions");
    }

    /** @brief Verify exact key ownership and bounded non-secret key-resolution contracts. */
    void key_material_contracts() {
        static_assert(!std::is_copy_constructible_v<key_derivation::Aes128Key>);
        static_assert(!std::is_copy_assignable_v<key_derivation::Aes128Key>);
        static_assert(std::is_nothrow_move_constructible_v<key_derivation::Aes128Key>);
        static_assert(std::is_nothrow_move_assignable_v<key_derivation::Aes128Key>);

        auto short_key = key_derivation::Aes128Key::import(Bytes(15));
        auto long_key = key_derivation::Aes128Key::adopt(SecureBuffer(Bytes(17)));
        auto exact_key = key_derivation::Aes128Key::adopt(SecureBuffer(Bytes(16, 0xA5)));
        expect(!short_key && !long_key && exact_key && exact_key.value().valid(),
               "AES-128 key ownership accepts exactly sixteen bytes");
        auto moved = std::move(exact_key.value());
        expect(moved.valid() && !exact_key.value().valid(),
               "moving an exact key transfers its only live SDK owner");

        const auto key_number = desfire::ev3::model::KeyNumber::make(2).value();
        auto empty_custom = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, key_number, {}, {}, {});
        auto long_custom = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, key_number, {}, {}, Bytes(1024));
        auto maximum_custom = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, key_number, {}, {}, Bytes(65536));
        auto oversized_custom = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, key_number, {}, {}, Bytes(65537));
        auto oversized_combined = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, key_number, {}, {}, Bytes(32768),
            Bytes(32769));
        auto invalid_key_set = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::offline_operation, key_number, {}, Byte{16}, {});
        auto invalid_purpose = key_derivation::Aes128DerivationContext::make(
            static_cast<key_derivation::KeyPurpose>(99), key_number, {}, {}, {});
        expect(empty_custom && long_custom && maximum_custom && !oversized_custom &&
                   !oversized_combined && !invalid_key_set && !invalid_purpose,
               "custom contexts allow construction-defined lengths within one 64-KiB bound");

        auto empty_reference = key_derivation::KeyReference::make({});
        auto maximum_reference = key_derivation::KeyReference::make(Bytes(1024, 0x5A));
        auto oversized_reference = key_derivation::KeyReference::make(Bytes(1025, 0x5A));
        expect(!empty_reference && maximum_reference && !oversized_reference,
               "opaque provider references are nonempty and allocation-bounded");

        const auto make_context = [&](key_derivation::KeyPurpose purpose) {
            return key_derivation::Aes128DerivationContext::make(purpose, key_number, {}, {}, {});
        };
        const auto make_reference = [] {
            return key_derivation::KeyReference::make(Bytes{0x01}).value();
        };
        std::stop_source cancellation;
        auto native = key_derivation::KeyRequest::make(
            make_reference(), make_context(key_derivation::KeyPurpose::authentication).value(),
            key_derivation::KeyScope::native, key_derivation::AuthenticationProfile::standard_aes,
            cancellation.get_token());
        auto missing_profile = key_derivation::KeyRequest::make(
            make_reference(), make_context(key_derivation::KeyPurpose::authentication).value());
        auto unexpected_profile = key_derivation::KeyRequest::make(
            make_reference(), make_context(key_derivation::KeyPurpose::offline_operation).value(),
            key_derivation::KeyScope::native, key_derivation::AuthenticationProfile::standard_aes);
        auto wrong_native_scope = key_derivation::KeyRequest::make(
            make_reference(), make_context(key_derivation::KeyPurpose::authentication).value(),
            key_derivation::KeyScope::iso_application,
            key_derivation::AuthenticationProfile::ev2_first);
        auto wrong_iso_scope = key_derivation::KeyRequest::make(
            make_reference(), make_context(key_derivation::KeyPurpose::authentication).value(),
            key_derivation::KeyScope::native, key_derivation::AuthenticationProfile::iso_aes);
        auto iso = key_derivation::KeyRequest::make(
            make_reference(), make_context(key_derivation::KeyPurpose::authentication).value(),
            key_derivation::KeyScope::iso_application,
            key_derivation::AuthenticationProfile::iso_aes);
        cancellation.request_stop();
        expect(native && native.value().cancellation().stop_requested() && !missing_profile &&
                   !unexpected_profile && !wrong_native_scope && !wrong_iso_scope && iso,
               "provider requests bind purpose, authentication family, scope, and cancellation");
    }

} // namespace

/** @brief Run the independent vectors and adversarial checks; return zero only on success. */
int main() {
    auto crypto = openssl_provider();
    expect(static_cast<bool>(crypto), "OpenSSL provider available");
    authentication_vectors(crypto.value());
    authentication_capabilities(crypto.value());
    messaging_vectors(crypto.value());
    messaging_failures(crypto.value());
    counter_and_plain(crypto.value());
    diversification(crypto.value());
    key_material_contracts();
    std::cout << "EV3 AES security vectors and fault-injection checks passed.\n";
    return EXIT_SUCCESS;
}
