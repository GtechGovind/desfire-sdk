/**
 * @file ev3_offline_test.cpp
 * @brief Offline known-answer checks with explicit shared-AES scope and failure evidence.
 *
 * TMAC and delegated DAM MAC expectations were computed independently with OpenSSL CLI from the
 * public field encodings described by the cited product datasheet and application notes. The
 * originality fixture is a published Light vector testing the shared construction. None of these
 * fixtures is claimed as a production EV3 card trace or an EV3 TMI schema.
 */
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/offline/delegated_application.hpp>
#include <desfire/ev3/offline/mifare_classic_license.hpp>
#include <desfire/ev3/offline/originality_signature.hpp>
#include <desfire/ev3/offline/transaction_mac.hpp>

#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {

    using namespace desfire;
    using namespace desfire::ev3::offline;

    /** @brief Stop the executable when an independently specified invariant is false. */
    void expect(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(EXIT_FAILURE);
        }
    }

    /** @brief Decode an explicit non-secret hexadecimal known-answer fixture. */
    Bytes hex(std::string_view text) {
        auto value = from_hex(text);
        expect(static_cast<bool>(value), "valid hexadecimal fixture");
        return std::move(value.value());
    }

    /** @brief Provider rejecting unsupported calls and injecting malformed outputs or exceptions.
     */
    class FaultCrypto final : public CryptoProvider {
    public:

        bool throw_failure{};
        bool return_failure{};
        bool enable_random{};
        std::size_t random_output_size{7};
        std::size_t calls{};

        /** @brief Inject a random-source failure, exception, or malformed output length. */
        Result<Bytes> random(std::size_t) override {
            ++calls;
            if (throw_failure) {
                throw std::runtime_error("injected");
            }
            if (enable_random) {
                return Bytes(random_output_size);
            }
            return invalid("Randomness is not part of offline verification");
        }

        /** @brief Inject a CBC output-length failure or a provider exception. */
        Result<Bytes> cbc(Cipher, ByteView, ByteView, ByteView, bool) override {
            ++calls;
            if (throw_failure) {
                throw std::runtime_error("injected");
            }
            return Bytes(15);
        }

        /** @brief Inject a CMAC output-length failure or a provider exception. */
        Result<Bytes> cmac(Cipher, ByteView, ByteView) override {
            ++calls;
            if (throw_failure) {
                throw std::runtime_error("injected");
            }
            if (return_failure) {
                return Error{ErrorCode::crypto, "injected CMAC failure"};
            }
            return Bytes(15);
        }

        /** @brief Return a signature mismatch or inject a provider exception. */
        Result<bool> verify_ecdsa(std::string_view, ByteView, ByteView, ByteView) override {
            ++calls;
            if (throw_failure) {
                throw std::runtime_error("injected");
            }
            return false;
        }
    };

    /** @brief Supply one published random field while delegating standard AES primitives. */
    class FixedRandomCrypto final : public CryptoProvider {
    public:

        /** @brief Retain a real primitive provider and the exact seven-byte fixture. */
        FixedRandomCrypto(std::shared_ptr<CryptoProvider> delegate, Bytes random)
            : delegate_(std::move(delegate)), random_(std::move(random)) {}

        /** @brief Return the fixed fixture only for the requested delegated-key width. */
        Result<Bytes> random(std::size_t size) override {
            if (size != random_.size()) {
                return invalid("Unexpected fixed-random request");
            }
            return random_;
        }

        /** @brief Delegate no-padding CBC without altering any input. */
        Result<Bytes> cbc(Cipher cipher, ByteView key, ByteView iv, ByteView input,
                          bool encrypt) override {
            return delegate_->cbc(cipher, key, iv, input, encrypt);
        }

        /** @brief Delegate complete CMAC without altering any input. */
        Result<Bytes> cmac(Cipher cipher, ByteView key, ByteView input) override {
            return delegate_->cmac(cipher, key, input);
        }

        /** @brief Delegate signature checks unused by the delegated-key vector. */
        Result<bool> verify_ecdsa(std::string_view curve, ByteView public_key, ByteView digest,
                                  ByteView signature) override {
            return delegate_->verify_ecdsa(curve, public_key, digest, signature);
        }

    private:

        std::shared_ptr<CryptoProvider> delegate_;
        Bytes random_;
    };

    /** @brief Record the exact CMAC call while delegating its cryptographic calculation. */
    class RecordingCmacCrypto final : public CryptoProvider {
    public:

        /** @brief Retain the real primitive provider used for the known-answer calculation. */
        explicit RecordingCmacCrypto(std::shared_ptr<CryptoProvider> delegate)
            : delegate_(std::move(delegate)) {}

        /** @brief Reject randomness because configuration MAC generation must be deterministic. */
        Result<Bytes> random(std::size_t) override {
            return invalid("Randomness is not part of delegated configuration MAC generation");
        }

        /** @brief Reject CBC because configuration MAC generation must only invoke CMAC. */
        Result<Bytes> cbc(Cipher, ByteView, ByteView, ByteView, bool) override {
            return invalid("CBC is not part of delegated configuration MAC generation");
        }

        /** @brief Record the primitive parameters and delegate the full AES-CMAC operation. */
        Result<Bytes> cmac(Cipher cipher, ByteView key, ByteView input) override {
            ++calls;
            last_cipher = cipher;
            last_key.assign(key.begin(), key.end());
            last_input.assign(input.begin(), input.end());
            return delegate_->cmac(cipher, key, input);
        }

        /** @brief Reject ECDSA because configuration MAC generation must only invoke CMAC. */
        Result<bool> verify_ecdsa(std::string_view, ByteView, ByteView, ByteView) override {
            return invalid("ECDSA is not part of delegated configuration MAC generation");
        }

        std::size_t calls{};
        Cipher last_cipher{Cipher::aes128};
        Bytes last_key{};
        Bytes last_input{};

    private:

        std::shared_ptr<CryptoProvider> delegate_;
    };

    /** @brief Verify the public AN12696 delegated EncK and DAM MAC example byte for byte. */
    void delegated_application_vectors(const std::shared_ptr<CryptoProvider>& crypto) {
        FixedRandomCrypto fixture(crypto, hex("F5E876FEE27560"));
        const auto dam_encryption_key = hex("22222222222222222222222222222222");
        const Bytes application_default_key(16);
        auto encrypted = encrypt_delegated_default_key_aes(fixture, dam_encryption_key,
                                                           application_default_key, 0);
        const auto expected_encrypted =
            hex("9232C82A913FA1CFCDC7ED5EC63AB45CE991C06A1F485156DB8C3CDCB689BD27");
        expect(encrypted && constant_time_equal(encrypted.value().view(), expected_encrypted),
               "AN12696 random, default key and version produce the documented EncK");

        auto application_id = desfire::ev3::model::ApplicationId::make(0x563412);
        expect(static_cast<bool>(application_id), "published delegated AID is valid");
        desfire::ev3::model::ApplicationConfiguration application{application_id.value()};
        application.key_settings = 0xEF;
        application.number_of_keys = 1;
        desfire::ev3::model::DelegatedApplicationConfiguration configuration{application, 0, 0,
                                                                             0x0040};
        auto mac = calculate_delegated_application_mac_aes(fixture,
                                                           hex("11111111111111111111111111111111"),
                                                           configuration, encrypted.value().view());
        expect(mac && constant_time_equal(mac.value(), hex("5D941683B901612B")),
               "AN12696 command fields and EncK produce the documented DAM MAC");

        auto delete_mac = calculate_delegated_application_delete_mac_aes(
            fixture, hex("11111111111111111111111111111111"), application_id.value());
        expect(delete_mac && constant_time_equal(delete_mac.value(), hex("DCD2F30E702C9370")),
               "documented delete variant authenticates opcode and little-endian AID");
    }

    /** @brief Verify NXP's SetConfiguration input layout and independent OpenSSL CMAC answers. */
    void delegated_configuration_vectors(const std::shared_ptr<CryptoProvider>& crypto) {
        RecordingCmacCrypto recording(crypto);
        const auto key = hex("11111111111111111111111111111111");

        auto regular = calculate_delegated_configuration_mac_aes(
            recording, key, hex("A0000003965643"), hex("A0000003965644"));
        expect(recording.calls == 1 && recording.last_cipher == Cipher::aes128 &&
                   constant_time_equal(recording.last_key, key),
               "delegated configuration uses one AES-128 CMAC with the supplied DAM MAC key");
        expect(constant_time_equal(recording.last_input, hex("07A0000003965643000000000000000000"
                                                             "07A0000003965644000000000000000000")),
               "DF-name lengths and values occupy two independent zero-padded 17-byte records");
        expect(regular && constant_time_equal(regular.value(), hex("D28CA69A54454B38")),
               "seven-byte DF names produce the independent OpenSSL CMAC known answer");

        auto maximum = calculate_delegated_configuration_mac_aes(
            recording, key, hex("00112233445566778899AABBCCDDEEFF"), {});
        expect(constant_time_equal(recording.last_input, hex("1000112233445566778899AABBCCDDEEFF"
                                                             "0000000000000000000000000000000000")),
               "sixteen-byte old and empty new names preserve both fixed-width records");
        expect(maximum && constant_time_equal(maximum.value(), hex("71723F068E859394")),
               "maximum and empty DF names produce the independent OpenSSL CMAC known answer");

        auto empty = calculate_delegated_configuration_mac_aes(recording, key, {}, {});
        expect(empty && constant_time_equal(empty.value(), hex("C1D0A147F101B536")),
               "two empty DF names authenticate the complete zero-filled 34-byte input");
    }

    /** @brief Verify the documented MFC license input and an independent OpenSSL CMAC answer. */
    void mfc_license_mac_vector(const std::shared_ptr<CryptoProvider>& crypto) {
        RecordingCmacCrypto recording(crypto);
        const auto key = hex("00112233445566778899AABBCCDDEEFF");
        const auto license = hex("0204A108B2");
        const auto sector_secrets =
            hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        auto mac = calculate_mfc_license_mac_aes(recording, key, license, sector_secrets);
        expect(recording.calls == 1 && recording.last_cipher == Cipher::aes128 &&
                   constant_time_equal(recording.last_key, key),
               "MFC license authorization invokes one AES-128 CMAC with the supplied key");
        expect(constant_time_equal(recording.last_input,
                                   hex("010204A108B2000102030405060708090A0B0C0D0E0F"
                                       "101112131415161718191A1B1C1D1E1F")),
               "MFC license MAC input is 01, complete license, then opaque sector secrets");
        expect(mac && constant_time_equal(mac.value(), hex("766EDC8921F03E2E")),
               "MFC license input produces the independent OpenSSL CMAC known answer");
    }

    /** @brief Verify independently generated session-key, MAC, and ReaderID known answers. */
    void transaction_vectors(CryptoProvider& crypto) {
        const auto key = hex("00112233445566778899AABBCCDDEEFF");
        const auto uid = hex("04782E21801D80");
        const std::array<std::uint32_t, 3> counters{1, 0x01020304, 0xFFFFFFFF};
        const std::array<std::string_view, 3> mac_keys{"2DB206D20F493AC4524EADE977E976B4",
                                                       "B20237FAB63F46765A10CB37B8CF3363",
                                                       "F04DFDB0F640DF7C29D2A1B72594B050"};
        const std::array<std::string_view, 3> encryption_keys{"A0DD3EA52546EC462FE0F466FEB3A62F",
                                                              "E83B0ECF0F38A4064DC837C22C6C0F2D",
                                                              "97D3A8A03983F015B89EAE1AAB8A13B2"};
        for (std::size_t index = 0; index < counters.size(); ++index) {
            auto keys = derive_transaction_mac_keys_aes(crypto, key, uid, counters[index]);
            expect(keys && constant_time_equal(keys.value().mac_key.view(), hex(mac_keys[index])) &&
                       constant_time_equal(keys.value().encryption_key.view(),
                                           hex(encryption_keys[index])),
                   "exact labels, little-endian TMC, and UID yield independent session keys");
        }
        const auto tmi = hex("3D02000000030000000000000000000000"
                             "10203000000000000000000000000000");
        const auto expected_mac = hex("1E285E485BA62DE1");
        auto calculated = calculate_transaction_mac_aes(crypto, hex(mac_keys[0]), tmi);
        expect(calculated && constant_time_equal(calculated.value(), expected_mac),
               "transaction CMAC uses independently derived key and alternating-byte truncation");
        auto verified = verify_transaction_mac_aes(crypto, key, uid, 1, tmi, expected_mac);
        expect(verified && verified.value(), "complete explicit transaction evidence verifies");
        auto wrong_counter = verify_transaction_mac_aes(crypto, key, uid, 2, tmi, expected_mac);
        expect(wrong_counter && !wrong_counter.value(),
               "wrong transaction counter does not verify");
        auto wrong_uid = uid;
        wrong_uid[0] ^= 1;
        auto rejected_uid =
            verify_transaction_mac_aes(crypto, key, wrong_uid, 1, tmi, expected_mac);
        expect(rejected_uid && !rejected_uid.value(), "wrong real UID does not verify");
        for (std::size_t index = 0; index < expected_mac.size(); ++index) {
            auto changed = expected_mac;
            changed[index] ^= 1;
            auto mismatch = verify_transaction_mac_aes(crypto, key, uid, 1, tmi, changed);
            expect(mismatch && !mismatch.value(), "every altered transmitted TMV byte fails");
        }
        auto changed_tmi = tmi;
        changed_tmi[19] ^= 1;
        auto changed = verify_transaction_mac_aes(crypto, key, uid, 1, changed_tmi, expected_mac);
        expect(changed && !changed.value(), "changed caller-supplied TMI fails verification");
        auto reader = decrypt_transaction_reader_id_aes(crypto, hex(encryption_keys[0]),
                                                        hex("4CBA5402F5723FA30DFCDF9477E623F5"));
        expect(reader && constant_time_equal(reader.value().view(),
                                             hex("00112233445566778899AABBCCDDEEFF")),
               "ReaderID decryption uses zero IV and preserves all sixteen bytes");
    }

    /** @brief Verify NXP's independently published raw-UID secp224r1 signature. */
    void originality_vector(CryptoProvider& crypto) {
        const auto public_key = hex("040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C5407557"
                                    "1AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D");
        const auto uid = hex("045A115A346180");
        const auto signature = hex("1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6D"
                                   "CD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61");
        auto verified = verify_originality_uid_signature(crypto, public_key, uid, signature);
        expect(verified && verified.value(), "AN12343 table 44 raw-UID signature verifies");
        auto bad_uid = uid;
        bad_uid[6] ^= 1;
        auto mismatch = verify_originality_uid_signature(crypto, public_key, bad_uid, signature);
        expect(mismatch && !mismatch.value(), "different UID fails the published signature");
        auto bad_signature = signature;
        bad_signature[0] ^= 1;
        auto tampered = verify_originality_uid_signature(crypto, public_key, uid, bad_signature);
        expect(tampered && !tampered.value(), "tampered ECDSA scalar fails verification");
    }

    /** @brief Check argument bounds and provider output lengths before exposing offline results. */
    void malformed_and_dependency_failures() {
        FaultCrypto crypto;
        const Bytes key(16);
        const Bytes uid(7);
        const Bytes tmi(16);
        const Bytes mac(8);
        expect(!derive_transaction_mac_keys_aes(crypto, key, uid, 0),
               "uncommitted zero TMC rejected");
        expect(!derive_transaction_mac_keys_aes(crypto, key, Bytes(4), 1),
               "Random ID is not a real UID");
        expect(!derive_transaction_mac_keys_aes(crypto, Bytes(15), uid, 1),
               "invalid master key rejected");
        expect(!calculate_transaction_mac_aes(crypto, key, {}),
               "empty transaction is not authenticated");
        expect(!verify_transaction_mac_aes(crypto, key, uid, 1, tmi, Bytes(7)),
               "short TMV rejected");
        expect(!decrypt_transaction_reader_id_aes(crypto, key, Bytes(15)),
               "short encrypted ReaderID rejected");
        expect(!verify_originality_uid_signature(crypto, Bytes(57), uid, Bytes(56)),
               "SEC1 key must use the explicit uncompressed representation");
        expect(!encrypt_delegated_default_key_aes(crypto, Bytes(15), key, 0),
               "short DAM encryption key rejected");
        auto aid = desfire::ev3::model::ApplicationId::make(1);
        desfire::ev3::model::DelegatedApplicationConfiguration delegated{
            desfire::ev3::model::ApplicationConfiguration{aid.value()}, 0, 0, 1};
        expect(!calculate_delegated_application_mac_aes(crypto, Bytes(15), delegated, Bytes(32)),
               "short DAM MAC key rejected");
        expect(!calculate_delegated_application_mac_aes(crypto, key, delegated, Bytes(31)),
               "short delegated EncK rejected");
        expect(!calculate_delegated_application_delete_mac_aes(crypto, Bytes(15), aid.value()),
               "short delegated-deletion DAM MAC key rejected");
        expect(!calculate_delegated_application_delete_mac_aes(
                   crypto, key, desfire::ev3::model::ApplicationId::make(0).value()),
               "delegated-deletion DAM MAC rejects the PICC identifier");
        expect(!calculate_delegated_configuration_mac_aes(crypto, Bytes(15), {}, {}),
               "delegated configuration rejects a short DAM MAC key");
        expect(!calculate_delegated_configuration_mac_aes(crypto, key, Bytes(17), {}),
               "delegated configuration rejects an oversized old DF name");
        expect(!calculate_delegated_configuration_mac_aes(crypto, key, {}, Bytes(17)),
               "delegated configuration rejects an oversized new DF name");
        expect(!calculate_mfc_license_mac_aes(crypto, Bytes(15), Bytes{0}, {}),
               "MFC license MAC rejects a short AES key");
        expect(!calculate_mfc_license_mac_aes(crypto, key, {}, {}),
               "MFC license MAC rejects an absent license");
        expect(!calculate_mfc_license_mac_aes(crypto, key, hex("02AABB"), {}),
               "MFC license MAC rejects a truncated block-pair list");
        expect(!calculate_mfc_license_mac_aes(crypto, key, Bytes{0}, Bytes(0xFFFFU)),
               "MFC license MAC rejects input exceeding its uint16 length");
        expect(crypto.calls == 0, "invalid offline arguments cause no primitive calls");

        crypto.enable_random = true;
        crypto.random_output_size = 6;
        auto short_random = encrypt_delegated_default_key_aes(crypto, key, key, 0);
        expect(!short_random && short_random.error().code == ErrorCode::crypto,
               "malformed delegated random-source length is rejected");
        crypto.random_output_size = 7;
        auto short_encrypted = encrypt_delegated_default_key_aes(crypto, key, key, 0);
        expect(!short_encrypted && short_encrypted.error().code == ErrorCode::crypto,
               "malformed delegated CBC output length is rejected");
        auto short_delete_mac =
            calculate_delegated_application_delete_mac_aes(crypto, key, aid.value());
        expect(!short_delete_mac && short_delete_mac.error().code == ErrorCode::crypto,
               "malformed delegated deletion CMAC output length is rejected");
        auto short_configuration_mac =
            calculate_delegated_configuration_mac_aes(crypto, key, {}, {});
        expect(!short_configuration_mac &&
                   short_configuration_mac.error().code == ErrorCode::crypto,
               "malformed delegated configuration CMAC output length is rejected");
        auto short_mfc_mac = calculate_mfc_license_mac_aes(crypto, key, Bytes{0}, {});
        expect(!short_mfc_mac && short_mfc_mac.error().code == ErrorCode::crypto,
               "malformed MFC license CMAC output length is rejected");
        crypto.return_failure = true;
        auto configuration_provider_failure =
            calculate_delegated_configuration_mac_aes(crypto, key, {}, {});
        expect(!configuration_provider_failure &&
                   configuration_provider_failure.error().code == ErrorCode::crypto,
               "delegated configuration preserves the CMAC provider failure");
        auto mfc_provider_failure = calculate_mfc_license_mac_aes(crypto, key, Bytes{0}, {});
        expect(!mfc_provider_failure && mfc_provider_failure.error().code == ErrorCode::crypto,
               "MFC license calculation preserves the CMAC provider failure");
        crypto.return_failure = false;

        auto short_key = derive_transaction_mac_keys_aes(crypto, key, uid, 1);
        expect(!short_key && short_key.error().code == ErrorCode::crypto,
               "short derived key is rejected");
        auto short_mac = calculate_transaction_mac_aes(crypto, key, tmi);
        expect(!short_mac && short_mac.error().code == ErrorCode::crypto,
               "short provider CMAC cannot be truncated");
        auto short_reader = decrypt_transaction_reader_id_aes(crypto, key, Bytes(16));
        expect(!short_reader && short_reader.error().code == ErrorCode::crypto,
               "short decrypted ReaderID is rejected");
        crypto.throw_failure = true;
        expect(!encrypt_delegated_default_key_aes(crypto, key, key, 0),
               "delegated random-source exception contained");
        expect(!calculate_delegated_application_delete_mac_aes(crypto, key, aid.value()),
               "delegated deletion CMAC exception contained");
        expect(!calculate_delegated_configuration_mac_aes(crypto, key, {}, {}),
               "delegated configuration CMAC exception contained");
        expect(!calculate_mfc_license_mac_aes(crypto, key, Bytes{0}, {}),
               "MFC license CMAC exception contained");
        expect(!derive_transaction_mac_keys_aes(crypto, key, uid, 1),
               "derivation exception contained");
        expect(!calculate_transaction_mac_aes(crypto, key, tmi), "CMAC exception contained");
        expect(!decrypt_transaction_reader_id_aes(crypto, key, Bytes(16)),
               "decryption exception contained");
        Bytes public_key(57);
        public_key[0] = 4;
        expect(!verify_originality_uid_signature(crypto, public_key, uid, Bytes(56)),
               "ECDSA exception contained");
    }

} // namespace

/** @brief Run offline crypto vectors without creating a card or using a reader transport. */
int main() {
    auto crypto = openssl_provider();
    expect(static_cast<bool>(crypto), "OpenSSL primitive provider available");
    delegated_application_vectors(crypto.value());
    delegated_configuration_vectors(crypto.value());
    mfc_license_mac_vector(crypto.value());
    transaction_vectors(*crypto.value());
    originality_vector(*crypto.value());
    malformed_and_dependency_failures();
    std::cout << "Offline delegated, transaction MAC, and originality checks passed.\n";
    return EXIT_SUCCESS;
}
