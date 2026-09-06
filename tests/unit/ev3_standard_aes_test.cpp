/**
 * @file ev3_standard_aes_test.cpp
 * @brief Independent AN0945 Standard AES authentication and secure-messaging vectors.
 */
#include <algorithm>
#include <cstdlib>
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/managed/card.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>
#include <desfire/ev3/security/standard_aes/authentication.hpp>
#include <desfire/ev3/security/standard_aes/session.hpp>
#include <desfire/transports/replay.hpp>
#include <iostream>
#include <stdexcept>

namespace {
    namespace key_derivation = desfire::ev3::security::key_derivation;

    using namespace desfire;
    using namespace desfire::ev3;
    using namespace desfire::ev3::model;
    using namespace desfire::ev3::native::checked;
    using namespace desfire::ev3::security::standard_aes;

    namespace managed = desfire::ev3::managed;
    using namespace desfire::transports;

    /** @brief Terminate on an externally visible behavior mismatch. */
    void expect(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(1);
        }
    }

    /** @brief Decode one fixed hexadecimal fixture. */
    Bytes hex(std::string_view text) {
        auto decoded = from_hex(text);
        expect(static_cast<bool>(decoded), "valid hexadecimal fixture");
        return std::move(decoded.value());
    }

    /** @brief Return one exact all-zero AES-128 fixture key with move-only ownership. */
    key_derivation::Aes128Key zero_key() {
        auto key = key_derivation::Aes128Key::import(Bytes(16));
        expect(static_cast<bool>(key), "exact AES-128 fixture key");
        return std::move(key.value());
    }

    /** @brief Delegate primitives while supplying an independently fixed authentication nonce. */
    class FixedNonceCrypto final : public CryptoProvider {
    public:

        /**
         * @brief Retain the production primitive provider and fixed test nonce.
         * @param provider AES implementation used without modification.
         * @param nonce Sixteen-byte public test nonce.
         */
        FixedNonceCrypto(std::shared_ptr<CryptoProvider> provider, Bytes nonce)
            : provider_(std::move(provider)), nonce_(std::move(nonce)) {}

        bool fail_random{};
        bool throw_cbc{};
        bool short_cbc{};

        /** @brief Return the fixed nonce or the requested injected failure. */
        Result<Bytes> random(std::size_t size) override {
            if (fail_random) {
                return Error{ErrorCode::crypto, "injected random failure"};
            }
            if (size != nonce_.size()) {
                return Error{ErrorCode::crypto, "unexpected random size"};
            }
            return nonce_;
        }

        /** @brief Delegate no-padding CBC to the production provider. */
        Result<Bytes> cbc(Cipher cipher, ByteView key, ByteView iv, ByteView input,
                          bool encrypt) override {
            if (throw_cbc) {
                throw std::runtime_error("injected CBC failure");
            }
            if (short_cbc) {
                return Bytes(input.empty() ? 0 : input.size() - 1);
            }
            return provider_->cbc(cipher, key, iv, input, encrypt);
        }

        /** @brief Delegate ordinary CMAC; Standard AES chained CMAC is implemented by the session.
         */
        Result<Bytes> cmac(Cipher cipher, ByteView key, ByteView input) override {
            return provider_->cmac(cipher, key, input);
        }

        /** @brief Preserve the provider contract for unrelated signature verification. */
        Result<bool> verify_ecdsa(std::string_view curve, ByteView key, ByteView data,
                                  ByteView signature) override {
            return provider_->verify_ecdsa(curve, key, data, signature);
        }

    private:

        std::shared_ptr<CryptoProvider> provider_;
        Bytes nonce_;
    };

    /** @brief Create a Standard AES session from one public AN0945 session-key fixture. */
    std::unique_ptr<Session> session(std::shared_ptr<CryptoProvider> crypto, std::string_view key) {
        AuthenticationMaterial material{SecureBuffer(hex(key))};
        auto created = Session::create(std::move(crypto), std::move(material));
        expect(static_cast<bool>(created), "Standard AES session fixture");
        return std::move(created.value());
    }

    /** @brief Independently wrap one native command in the short proprietary APDU envelope. */
    Bytes wrap(Byte command, ByteView data) {
        Bytes output{0x90, command, 0x00, 0x00};
        if (!data.empty()) {
            output.push_back(static_cast<Byte>(data.size()));
        }
        append(output, data);
        output.push_back(0x00);
        return output;
    }

    /** @brief Append wrapped-native success status to status-free response data. */
    Bytes done(ByteView data) {
        Bytes output(data.begin(), data.end());
        append(output, Bytes{0x91, 0x00});
        return output;
    }

    /** @brief Append one wrapped-native status byte other than success. */
    Bytes done_with_status(ByteView data, Byte status) {
        Bytes output(data.begin(), data.end());
        append(output, Bytes{0x91, status});
        return output;
    }

    /**
     * @brief Build an independent 0xAA transcript that derives a chosen published session key.
     * @param steps Replay transcript receiving both authentication frames.
     * @param base AES primitive implementation used only to encrypt the explicit nonce layout.
     * @param session_key Desired sixteen-byte Standard-AES session key.
     * @param card_key Native card key selector carried by AuthenticateAES.
     * @return Mutable fault-injection provider whose fixed nonce matches the transcript.
     */
    std::shared_ptr<FixedNonceCrypto>
    append_authentication(std::deque<ReplayStep>& steps,
                          const std::shared_ptr<CryptoProvider>& base, ByteView session_key,
                          Byte card_key = 0) {
        expect(session_key.size() == 16, "managed Standard AES session-key fixture size");
        Bytes random_a = hex("00000000010203040506070800000000");
        Bytes random_b = hex("00000000111213141516171800000000");
        std::ranges::copy(session_key.first(4), random_a.begin());
        std::ranges::copy(session_key.subspan(4, 4), random_b.begin());
        std::ranges::copy(session_key.subspan(8, 4), random_a.begin() + 12);
        std::ranges::copy(session_key.subspan(12, 4), random_b.begin() + 12);

        const Bytes zero(16);
        auto encrypted_b = base->cbc(Cipher::aes128, zero, zero, random_b, true).value();
        Bytes proof = random_a;
        std::rotate(random_b.begin(), random_b.begin() + 1, random_b.end());
        append(proof, random_b);
        auto encrypted_proof = base->cbc(Cipher::aes128, zero, encrypted_b, proof, true).value();
        std::rotate(random_a.begin(), random_a.begin() + 1, random_a.end());
        auto encrypted_a =
            base->cbc(Cipher::aes128, zero, ByteView(encrypted_proof).last(16), random_a, true)
                .value();

        steps.push_back({wrap(0xAA, Bytes{card_key}), done_with_status(encrypted_b, 0xAF)});
        steps.push_back({wrap(0xAF, encrypted_proof), done(encrypted_a)});
        std::rotate(random_a.begin(), random_a.end() - 1, random_a.end());
        return std::make_shared<FixedNonceCrypto>(base, std::move(random_a));
    }

    /** @brief Verify command 0xAA chaining, mutual proof, and session-key derivation. */
    void authentication_vector() {
        auto base = openssl_provider().value();
        FixedNonceCrypto crypto(base, hex("2347C1557F80707ABDFF86BF9D965CA7"));
        std::size_t frame = 0;
        const auto exchange = [&](Byte command, ByteView payload) -> Result<native::raw::Response> {
            ++frame;
            if (frame == 1) {
                expect(command == 0xAA && std::ranges::equal(payload, hex("00")),
                       "AN0945 table 22 AuthenticateAES request");
                return native::raw::Response{0xAF, hex("C5537C8EFFFCC7E152C27831AFD383BA")};
            }
            expect(command == 0xAF &&
                       std::ranges::equal(payload,
                                          hex("1EF512D957973AED7E6E13991EB0FB431B373EA23400A3AC"
                                              "0B7749CD6FB1C328")),
                   "AN0945 table 22 chained host proof");
            return native::raw::Response{0x00, hex("FFC212245F03DB0EA0645A495190952A")};
        };

        auto authenticated = authenticate(crypto, 0, Bytes(16), exchange);
        expect(authenticated && frame == 2 &&
                   std::ranges::equal(authenticated.value().session_key.view(),
                                      hex("2347C1551EA0353A9D965CA7B52FCA84")),
               "AN0945 table 22 session-key derivation");

        frame = 0;
        crypto.fail_random = true;
        auto no_random = authenticate(crypto, 0, Bytes(16), exchange);
        expect(!no_random && no_random.error().outcome == Outcome::not_sent && frame == 0,
               "random failure stops before card I/O");
        crypto.fail_random = false;
        auto invalid_key = authenticate(crypto, 64, Bytes(16), exchange);
        expect(!invalid_key && invalid_key.error().code == ErrorCode::invalid_argument &&
                   frame == 0,
               "invalid selector stops before card I/O");

        auto malformed =
            authenticate(crypto, 0, Bytes(16), [](Byte, ByteView) -> Result<native::raw::Response> {
                return native::raw::Response{0xAF, Bytes(15)};
            });
        expect(!malformed && malformed.error().code == ErrorCode::malformed_response,
               "truncated encrypted nonce is rejected");

        std::size_t bad_frame = 0;
        auto bad_proof = authenticate(
            crypto, 0, Bytes(16), [&](Byte, ByteView) -> Result<native::raw::Response> {
                ++bad_frame;
                if (bad_frame == 1) {
                    return native::raw::Response{0xAF, hex("C5537C8EFFFCC7E152C27831AFD383BA")};
                }
                return native::raw::Response{0x00, Bytes(16)};
            });
        expect(!bad_proof && bad_proof.error().code == ErrorCode::authentication &&
                   bad_proof.error().outcome == Outcome::unknown,
               "wrong card proof never establishes a session");
    }

    /** @brief Verify AN0945 tables 23 and 24 for Full write/read and chained IV state. */
    void full_vectors() {
        auto crypto = openssl_provider().value();
        auto aes = session(crypto, "227EAC508FB2D130E0451988D51F8DD0");
        const auto header = hex("020000000F0000");
        const auto data = hex("112233445566778899AABBCCDDEEFF");
        auto write = aes->prepare_full(0x3D, header, data);
        expect(write && write.value() ==
                            hex("020000000F00009B9915A7572364D05CDF03FBA9B0F69EA88E3C4F0DEE3EDAB9"
                                "ACC8BE88B7DAC9"),
               "AN0945 table 23 Full write CRC, zero padding, encryption and wire payload");
        auto write_response = aes->verify_response({0x00, hex("B987074D3F60EEF6")});
        expect(write_response && write_response.value().empty(), "AN0945 table 23 response CMAC");

        auto read = aes->prepare_mac(0xBD, header, {});
        expect(read && read.value() == header,
               "AN0945 table 24 read CMAC updates IV without transmission");
        auto read_response = aes->verify_and_decrypt_full_response(
            {0x00, hex("3C624B56FF16798F960E341E10EEA8CF5155D67AC6273EE5DDEB90E16228DF03")},
            data.size());
        expect(read_response && read_response.value() == data,
               "AN0945 table 24 response decryption, CRC and zero padding");
    }

    /** @brief Verify AN0945 tables 25 and 26 for transmitted and update-only CMACs. */
    void mac_vectors() {
        auto crypto = openssl_provider().value();
        auto aes = session(crypto, "0AAF803DD2A6252D851B69B9E4F63801");
        const auto header = hex("03000000150000");
        const auto data = hex("0102030405060708090A0B0C0D0E0F101112131415");
        auto write = aes->prepare_mac(0x3D, header, data);
        Bytes expected = header;
        append(expected, data);
        append(expected, hex("BEF5B687604234F7"));
        expect(write && write.value() == expected, "AN0945 table 25 command CMAC");
        auto write_response = aes->verify_response({0x00, hex("A6589DC8FC47D2E4")});
        expect(write_response && write_response.value().empty(), "AN0945 table 25 response CMAC");

        auto read = aes->prepare_mac(0xBD, header, {});
        expect(read && read.value() == header, "AN0945 table 26 update-only command CMAC");
        Bytes response = data;
        append(response, hex("DF5C0EA3D6331E4F"));
        auto verified = aes->verify_response({0x00, response});
        expect(verified && verified.value() == data, "AN0945 table 26 response data and CMAC");
    }

    /** @brief Verify update-only request CMAC and mandatory response CMAC for Plain data. */
    void plain_vector() {
        auto crypto = openssl_provider().value();
        auto aes = session(crypto, "CB45D8074BD262A526782FEF5049B5D5");
        auto request = aes->prepare_plain(0x45, {}, {});
        expect(request && request.value().empty(),
               "AN0945 table 34 Plain request CMAC is not transmitted");
        auto response = aes->accept_plain_response({0x00, hex("0F84C5D5E829E923C3B5")});
        expect(response && response.value() == hex("0F84"),
               "AN0945 table 34 Plain response CMAC is mandatory and verified");
    }

    /** @brief Verify current-key ChangeKey construction from AN0945 table 33. */
    void change_key_vector() {
        auto crypto = openssl_provider().value();
        auto aes = session(crypto, "04BC99A81DB7293FAA86CA225ECD7660");
        const auto key_zero = KeyNumber::make(0).value();
        auto command =
            change_aes_key(key_zero, hex("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"), 1, key_zero);
        expect(static_cast<bool>(command), "valid current-key command");
        auto wire = aes->prepare_full(command.value().opcode(), command.value().header(),
                                      command.value().data());
        expect(wire &&
                   wire.value() ==
                       hex("00B679B08051DA0A62D14C3544A968C943636A2815165E1FB7C1DCC839CFCD3D94"),
               "AN0945 table 33 ChangeKey CRC, zero padding, encryption and payload");
        expect(command.value().invalidates_session() &&
                   command.value().response_mode() == CommunicationMode::plain,
               "changing the authenticated key expects no CMAC and ends the session");

        auto other = session(crypto, "5DD4CBFC20A1988E1CDBAE322B315D57");
        const auto key_one = KeyNumber::make(1).value();
        auto other_command = change_aes_key(key_one, hex("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), 3,
                                            key_zero, hex("00112233445566778899AABBCCDDEEFF"));
        expect(other_command &&
                   std::ranges::equal(other_command.value().data(),
                                      hex("A0B08090E0F0C0D020300010607040500390DBDA4D")),
               "AN0945 table 32 typed XOR key data and new-key CRC");
        auto other_wire =
            other->prepare_full(other_command.value().opcode(), other_command.value().header(),
                                other_command.value().data());
        expect(other_wire &&
                   other_wire.value() ==
                       hex("01F19B5BB7BE967FE0FD990366DDF523DA66C9DB66212B70B88FDA821419C302CA"),
               "ChangeKey case 1 inserts command CRC before the documented new-key CRC");

        auto key_set = session(crypto, "5DD4CBFC20A1988E1CDBAE322B315D57");
        auto key_set_command = change_aes_key(key_one, hex("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), 3,
                                              key_zero, hex("00112233445566778899AABBCCDDEEFF"), 2);
        expect(key_set_command && !key_set_command.value().requires_ev2_session(),
               "ChangeKeyEV2 C6 accepts a verified Standard AES session");
        auto key_set_wire =
            key_set->prepare_full(key_set_command.value().opcode(),
                                  key_set_command.value().header(), key_set_command.value().data());
        expect(key_set_wire &&
                   key_set_wire.value() ==
                       hex("0201F19B5BB7BE967FE0FD990366DDF523DA2C09FA85FC566D08B458E2916C487115"),
               "Standard AES ChangeKeyEV2 protects key-set and key selectors as clear header");
        auto key_set_response = key_set->verify_response({0x00, hex("87AC9B78DD93AB4A")});
        expect(key_set_response && key_set_response.value().empty(),
               "Standard AES ChangeKeyEV2 verifies the response CMAC");
    }

    /** @brief Verify all key-set lifecycle commands use documented Standard AES MAC data fields. */
    void key_set_standard_aes_vectors() {
        auto aes = session(openssl_provider().value(), "CB45D8074BD262A526782FEF5049B5D5");

        auto initialize = initialize_key_set(2);
        auto initialize_wire = aes->prepare_mac(
            initialize.value().opcode(), initialize.value().header(), initialize.value().data());
        expect(initialize_wire && initialize_wire.value() == hex("0202B5101F88AB55606A"),
               "Standard AES InitializeKeySet transmits data and its chained CMAC");
        expect(static_cast<bool>(aes->verify_response({0x00, hex("7EEACCE0788E0066")})),
               "Standard AES InitializeKeySet verifies its response CMAC");

        auto finalize = finalize_key_set(2, 0x44);
        auto finalize_wire = aes->prepare_mac(finalize.value().opcode(), finalize.value().header(),
                                              finalize.value().data());
        expect(finalize_wire && finalize_wire.value() == hex("0244D5A1DB284A3B8F77"),
               "Standard AES FinalizeKeySet transmits data and its chained CMAC");
        expect(static_cast<bool>(aes->verify_response({0x00, hex("DED51689CEB54803")})),
               "Standard AES FinalizeKeySet verifies its response CMAC");

        auto roll = roll_key_set(2);
        auto roll_wire =
            aes->prepare_mac(roll.value().opcode(), roll.value().header(), roll.value().data());
        expect(roll_wire && roll_wire.value() == hex("023362057C8F256DFD"),
               "Standard AES RollKeySet transmits data and its chained CMAC");
        expect(static_cast<bool>(aes->verify_response({0x00, hex("C67A8AD89BB29471")})),
               "Standard AES RollKeySet verifies its response before authentication reset");
    }

    /** @brief Verify RestoreTransfer's documented data boundary and Standard-AES CMAC chain. */
    void restore_transfer_vector() {
        auto aes = session(openssl_provider().value(), "CB45D8074BD262A526782FEF5049B5D5");
        auto command = restore_transfer(FileNumber::make(2).value(), FileNumber::make(3).value(),
                                        CommunicationMode::mac);
        auto wire = aes->prepare_mac(command.value().opcode(), command.value().header(),
                                     command.value().data());
        expect(wire && wire.value() == hex("020374B2B7D2D804F92E"),
               "RestoreTransfer sends target then source followed by Standard-AES CMAC");
        auto response = aes->verify_response({0x00, hex("63B5D4355EC59A02")});
        expect(response && response.value().empty(),
               "RestoreTransfer verifies the chained Standard-AES response CMAC");
    }

    /** @brief Assert fail-closed behavior for CMAC, ciphertext, CRC, and phase misuse. */
    void integrity_failures() {
        auto crypto = openssl_provider().value();
        auto mac = session(crypto, "0AAF803DD2A6252D851B69B9E4F63801");
        expect(static_cast<bool>(mac->prepare_mac(
                   0x3D, hex("03000000150000"), hex("0102030405060708090A0B0C0D0E0F101112131415"))),
               "prepare tampered CMAC fixture");
        auto bad_mac = mac->verify_response({0x00, hex("A6589DC8FC47D2E5")});
        expect(!bad_mac && bad_mac.error().code == ErrorCode::integrity &&
                   bad_mac.error().outcome == Outcome::unknown,
               "response CMAC tampering invalidates the session");
        auto reused = mac->prepare_mac(0x45, {}, {});
        expect(!reused && reused.error().code == ErrorCode::session_invalid,
               "invalidated IV state cannot be reused");

        auto full = session(crypto, "227EAC508FB2D130E0451988D51F8DD0");
        expect(static_cast<bool>(full->prepare_mac(0xBD, hex("020000000F0000"), {})),
               "prepare malformed encrypted response fixture");
        auto short_response = full->verify_and_decrypt_full_response({0x00, Bytes(15)}, 15);
        expect(!short_response && short_response.error().code == ErrorCode::integrity,
               "non-block ciphertext is rejected");

        auto crc = session(crypto, "227EAC508FB2D130E0451988D51F8DD0");
        expect(static_cast<bool>(crc->prepare_mac(0xBD, hex("020000000F0000"), {})),
               "prepare bad CRC fixture");
        auto ciphertext = hex("3C624B56FF16798F960E341E10EEA8CF5155D67AC6273EE5DDEB90E16228DF03");
        ciphertext.back() ^= 1;
        auto bad_crc = crc->verify_and_decrypt_full_response({0x00, ciphertext}, 15);
        expect(!bad_crc && bad_crc.error().code == ErrorCode::integrity,
               "ciphertext or CRC tampering is rejected");
    }

    /** @brief Verify public Card emits the exact wrapped 0xAA exchange and installs the session. */
    void card_wire_vector() {
        auto crypto = std::make_shared<FixedNonceCrypto>(openssl_provider().value(),
                                                         hex("2347C1557F80707ABDFF86BF9D965CA7"));
        auto transport = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("90AA0000010000"), hex("C5537C8EFFFCC7E152C27831AFD383BA91AF")},
            {hex("90AF0000201EF512D957973AED7E6E13991EB0FB431B373EA23400A3AC0B7749CD6F"
                 "B1C32800"),
             hex("FFC212245F03DB0EA0645A495190952A9100")}});
        auto card = managed::Card::connect(transport, crypto).value();
        auto authenticated =
            card->authenticate_standard_aes(KeyNumber::make(0).value(), zero_key());
        expect(authenticated && transport->remaining() == 0,
               "Card performs exact wrapped Standard AES handshake once");

        auto nonfirst =
            card->authenticate_ev2_non_first_aes(KeyNumber::make(0).value(), zero_key());
        expect(!nonfirst && nonfirst.error().code == ErrorCode::session_invalid,
               "EV2 NonFirst cannot reuse Standard AES state");

        DelegatedApplicationConfiguration delegated{
            ApplicationConfiguration{ApplicationId::make(0x123456).value()}, 0, 0, 0x40};
        auto dam = card->create_delegated_application(delegated, Bytes(32), Bytes(8));
        expect(!dam && dam.error().code == ErrorCode::authentication &&
                   dam.error().outcome == Outcome::not_sent && transport->remaining() == 0,
               "EV2-only delegated creation rejects a Standard AES session before I/O");
        auto deleted =
            card->delete_delegated_application(ApplicationId::make(0x123456).value(), Bytes(8));
        expect(!deleted && deleted.error().code == ErrorCode::authentication &&
                   deleted.error().outcome == Outcome::not_sent && transport->remaining() == 0,
               "delegated deletion rejects a non-DAM authentication key before I/O");
    }

    /** @brief Exercise Card dispatch against the published Full, MAC, and Plain AES vectors. */
    void card_secure_messaging_vectors() {
        auto base = openssl_provider().value();

        {
            std::deque<ReplayStep> steps;
            auto crypto =
                append_authentication(steps, base, hex("227EAC508FB2D130E0451988D51F8DD0"));
            const auto header = hex("020000000F0000");
            const auto data = hex("112233445566778899AABBCCDDEEFF");
            steps.push_back(
                {wrap(0x3D, hex("020000000F00009B9915A7572364D05CDF03FBA9B0F69EA88E3C4F0DEE3EDAB9"
                                "ACC8BE88B7DAC9")),
                 done(hex("B987074D3F60EEF6"))});
            steps.push_back(
                {wrap(0xBD, header),
                 done(hex("3C624B56FF16798F960E341E10EEA8CF5155D67AC6273EE5DDEB90E16228DF03"))});
            auto transport = std::make_shared<ReplayTransport>(std::move(steps));
            auto card = managed::Card::connect(transport, crypto).value();
            expect(static_cast<bool>(
                       card->authenticate_standard_aes(KeyNumber::make(0).value(), zero_key())),
                   "managed Full fixture authenticates through 0xAA");
            expect(static_cast<bool>(card->write_data(FileNumber::make(2).value(),
                                                      Offset::make(0).value(), data,
                                                      CommunicationMode::full)),
                   "Card dispatch emits the published Full write");
            auto read = card->read_data(FileNumber::make(2).value(), Offset::make(0).value(),
                                        ByteCount::make(15).value(), CommunicationMode::full);
            expect(read && read.value() == data && transport->remaining() == 0,
                   "Card dispatch decrypts and verifies the published Full read");
        }

        {
            std::deque<ReplayStep> steps;
            auto crypto =
                append_authentication(steps, base, hex("0AAF803DD2A6252D851B69B9E4F63801"));
            const auto header = hex("03000000150000");
            const auto data = hex("0102030405060708090A0B0C0D0E0F101112131415");
            Bytes write = header;
            append(write, data);
            append(write, hex("BEF5B687604234F7"));
            steps.push_back({wrap(0x3D, write), done(hex("A6589DC8FC47D2E4"))});
            Bytes response = data;
            append(response, hex("DF5C0EA3D6331E4F"));
            steps.push_back({wrap(0xBD, header), done(response)});
            Bytes tampered = data;
            append(tampered, Bytes(8));
            steps.push_back({wrap(0xBD, header), done(tampered)});
            auto transport = std::make_shared<ReplayTransport>(std::move(steps));
            auto card = managed::Card::connect(transport, crypto).value();
            expect(static_cast<bool>(
                       card->authenticate_standard_aes(KeyNumber::make(0).value(), zero_key())),
                   "managed MAC fixture authenticates through 0xAA");
            expect(static_cast<bool>(card->write_data(FileNumber::make(3).value(),
                                                      Offset::make(0).value(), data,
                                                      CommunicationMode::mac)),
                   "Card dispatch emits the published MAC write");
            auto read = card->read_data(FileNumber::make(3).value(), Offset::make(0).value(),
                                        ByteCount::make(21).value(), CommunicationMode::mac);
            expect(read && read.value() == data, "Card dispatch verifies the published MAC read");
            auto rejected = card->read_data(FileNumber::make(3).value(), Offset::make(0).value(),
                                            ByteCount::make(21).value(), CommunicationMode::mac);
            expect(!rejected && rejected.error().code == ErrorCode::integrity,
                   "managed MAC tampering is rejected");
            auto invalid = card->read_data(FileNumber::make(3).value(), Offset::make(0).value(),
                                           ByteCount::make(21).value(), CommunicationMode::mac);
            expect(!invalid && invalid.error().code == ErrorCode::session_invalid &&
                       transport->remaining() == 0,
                   "Card invalidates the Standard AES session after integrity failure");
        }

        {
            std::deque<ReplayStep> steps;
            auto crypto =
                append_authentication(steps, base, hex("CB45D8074BD262A526782FEF5049B5D5"));
            steps.push_back({wrap(0x45, {}), done(hex("0F84C5D5E829E923C3B5"))});
            auto transport = std::make_shared<ReplayTransport>(std::move(steps));
            auto card = managed::Card::connect(transport, crypto).value();
            expect(static_cast<bool>(
                       card->authenticate_standard_aes(KeyNumber::make(0).value(), zero_key())),
                   "managed Plain fixture authenticates through 0xAA");
            auto settings = get_key_settings();
            auto response = card->execute(settings.value());
            expect(response && response.value() == hex("0F84") && transport->remaining() == 0,
                   "Card verifies the mandatory CMAC on an authenticated Plain response");
        }

        {
            std::deque<ReplayStep> steps;
            auto crypto =
                append_authentication(steps, base, hex("CB45D8074BD262A526782FEF5049B5D5"), 0x10);
            steps.push_back(
                {wrap(0xDA, hex("563412A0A1A2A3A4A5A6A7")), done(hex("71E425F72D1ABEDC"))});
            auto transport = std::make_shared<ReplayTransport>(std::move(steps));
            auto card = managed::Card::connect(transport, crypto).value();
            expect(static_cast<bool>(
                       card->authenticate_standard_aes(KeyNumber::make(0x10).value(), zero_key())),
                   "delegated deletion fixture authenticates with PICCDAMAuthKey");
            auto deleted = card->delete_delegated_application(ApplicationId::make(0x123456).value(),
                                                              hex("A0A1A2A3A4A5A6A7"));
            expect(
                deleted && transport->remaining() == 0,
                "Standard AES delegated deletion sends no command MAC and verifies response CMAC");
        }
    }

    /** @brief Ensure malformed and throwing CBC providers invalidate a public Card session. */
    void card_provider_failures() {
        auto run = [](bool throws) {
            auto base = openssl_provider().value();
            std::deque<ReplayStep> steps;
            auto crypto =
                append_authentication(steps, base, hex("CB45D8074BD262A526782FEF5049B5D5"));
            auto transport = std::make_shared<ReplayTransport>(std::move(steps));
            auto card = managed::Card::connect(transport, crypto).value();
            expect(static_cast<bool>(
                       card->authenticate_standard_aes(KeyNumber::make(0).value(), zero_key())),
                   "provider-failure fixture authenticates");
            crypto->throw_cbc = throws;
            crypto->short_cbc = !throws;
            auto failed = card->free_memory();
            expect(!failed &&
                       failed.error().code == (throws ? ErrorCode::internal : ErrorCode::crypto) &&
                       failed.error().outcome == Outcome::not_sent,
                   "Standard AES CMAC provider failure is contained before transport I/O");
            crypto->throw_cbc = false;
            crypto->short_cbc = false;
            auto invalid = card->free_memory();
            expect(!invalid && invalid.error().code == ErrorCode::session_invalid &&
                       transport->remaining() == 0,
                   "provider failure leaves no reusable Standard AES session");
        };
        run(false);
        run(true);
    }

} // namespace

/** @brief Run independent Standard AES authentication and messaging regressions. */
int main() {
    authentication_vector();
    full_vectors();
    mac_vectors();
    plain_vector();
    change_key_vector();
    key_set_standard_aes_vectors();
    restore_transfer_vector();
    integrity_failures();
    card_wire_vector();
    card_secure_messaging_vectors();
    card_provider_failures();
}
