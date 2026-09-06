/** @file ev3_card_test.cpp
 * @brief Managed First/Full-read/NonFirst/counter/recovery tests with independent peer primitives.
 */
#include <algorithm>
#include <cstdlib>
#include <desfire/crypto/openssl.hpp>
#include <desfire/ev3/managed/card.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/transports/callback.hpp>
#include <desfire/transports/replay.hpp>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <stop_token>

namespace {
    namespace key_derivation = desfire::ev3::security::key_derivation;
    namespace managed = desfire::ev3::managed;

    using namespace desfire;
    using namespace desfire::ev3;
    using namespace desfire::ev3::model;
    using namespace desfire::ev3::native::checked;
    using namespace desfire::transports;

    /** @brief Check externally observable protocol behavior without NDEBUG dependence. */
    void expect(bool condition, std::string_view text) {
        if (!condition) {
            std::cerr << "FAILED: " << text << '\n';
            std::exit(1);
        }
    }

    /** @brief Decode a fixed public known-answer fixture. */
    Bytes hex(std::string_view text) {
        auto r = from_hex(text);
        expect(static_cast<bool>(r), "hex fixture");
        return std::move(r.value());
    }

    /** @brief Import one exact AES-128 key into move-only test ownership. */
    key_derivation::Aes128Key aes_key(ByteView bytes) {
        auto key = key_derivation::Aes128Key::import(bytes);
        expect(static_cast<bool>(key), "exact AES-128 fixture key");
        return std::move(key.value());
    }

    /** @brief Return one exact all-zero AES-128 fixture key. */
    key_derivation::Aes128Key zero_key() {
        return aes_key(Bytes(16));
    }

    /** @brief Inject only the published reader nonce; all primitives remain the real provider. */
    class NonceCrypto final : public CryptoProvider {
    public:

        /**
         * @brief Retain the provider and one exact deterministic authentication nonce.
         * @param provider Primitive provider used without modifying its AES behavior.
         * @param nonce Public test nonce returned only when its exact width is requested.
         */
        explicit NonceCrypto(std::shared_ptr<CryptoProvider> provider,
                             Bytes nonce = hex("B04D0787C93EE0CC8CACC8E86F16C6FE"))
            : provider_(std::move(provider)), nonce_(std::move(nonce)) {}

        /** @brief Return the fixed AN12343 nonce only inside this test. */
        Result<Bytes> random(std::size_t size) override {
            if (size != nonce_.size()) {
                return Error{ErrorCode::crypto, "Unexpected fixture random-byte request"};
            }
            return nonce_;
        }

        /** @brief Delegate AES without duplicating secure-session behavior. */
        Result<Bytes> cbc(Cipher c, ByteView k, ByteView v, ByteView d, bool e) override {
            return provider_->cbc(c, k, v, d, e);
        }

        bool fail_cmac{};
        bool throw_cmac{};

        /** @brief Inject local CMAC failure or delegate without duplicating the session engine. */
        Result<Bytes> cmac(Cipher c, ByteView k, ByteView d) override {
            if (throw_cmac) {
                throw std::runtime_error("injected provider exception");
            }
            if (fail_cmac) {
                return Error{ErrorCode::crypto, "injected preparation failure"};
            }
            return provider_->cmac(c, k, d);
        }

        /** @brief Preserve the primitive contract for signature operations. */
        Result<bool> verify_ecdsa(std::string_view c, ByteView k, ByteView d, ByteView s) override {
            return provider_->verify_ecdsa(c, k, d, s);
        }

    private:

        std::shared_ptr<CryptoProvider> provider_;
        Bytes nonce_;
    };

    /** @brief Return a fixed AES key while recording public Card derivation API use. */
    class FixedDeriver final : public key_derivation::Aes128KeyDeriver {
    public:

        /**
         * @brief Select deterministic exact output for the derivation fixture.
         * @param output Exact sixteen-byte derived key.
         */
        explicit FixedDeriver(Bytes output = Bytes(16)) : output_(std::move(output)) {}

        std::size_t calls{};
        std::size_t master_key_size{};
        std::size_t diversification_size{};
        key_derivation::KeyPurpose purpose{key_derivation::KeyPurpose::offline_operation};
        model::KeyNumber key_number{model::KeyNumber::make(0).value()};

        /** @brief Record the borrowed request and return a deterministic AES-128 key. */
        Result<key_derivation::Aes128Key>
        derive(const key_derivation::Aes128Key& master_key,
               const key_derivation::Aes128DerivationContext& context) override {
            ++calls;
            master_key_size = master_key.view().size();
            diversification_size = context.diversification_input().size();
            purpose = context.purpose();
            key_number = context.key_number();
            return aes_key(output_);
        }

    private:

        Bytes output_;
    };

    /** @brief Deterministic provider with explicit failure, exception, and reentry hooks. */
    class FixedProvider final : public key_derivation::Aes128KeyProvider {
    public:

        /** @brief Provider behavior selected independently for each acceptance case. */
        enum class Behavior { success, failure, exception, moved_from };

        /**
         * @brief Configure a deterministic exportable-key provider fixture.
         * @param output Exact success key returned in fresh move-only ownership.
         * @param behavior Resolution result to inject.
         */
        explicit FixedProvider(Bytes output = Bytes(16), Behavior behavior = Behavior::success)
            : output_(std::move(output)), behavior_(behavior) {}

        std::size_t calls{};
        bool saw_cancellation{};
        key_derivation::AuthenticationProfile profile{
            key_derivation::AuthenticationProfile::standard_aes};
        key_derivation::KeyScope scope{key_derivation::KeyScope::native};
        std::function<void(const key_derivation::KeyRequest&)> during_resolution;

        /** @brief Record non-secret request data and inject the selected synchronous result. */
        Result<key_derivation::Aes128Key>
        resolve(const key_derivation::KeyRequest& request) override {
            ++calls;
            profile = request.authentication_profile().value();
            scope = request.scope();
            if (during_resolution) {
                during_resolution(request);
            }
            saw_cancellation = request.cancellation().stop_requested();
            switch (behavior_) {
            case Behavior::success:
                return aes_key(output_);
            case Behavior::failure:
                return Error{ErrorCode::crypto, "untrusted fixture detail", Outcome::unknown,
                             0x91AE};
            case Behavior::exception:
                throw std::runtime_error("untrusted fixture exception");
            case Behavior::moved_from: {
                auto imported = key_derivation::Aes128Key::import(output_);
                expect(static_cast<bool>(imported), "provider moved-from fixture key");
                auto retained = std::move(imported.value());
                static_cast<void>(retained);
                return std::move(imported.value());
            }
            }
            return Error{ErrorCode::internal, "unreachable fixture behavior"};
        }

    private:

        Bytes output_;
        Behavior behavior_;
    };

    /** @brief Build one validated authentication-purpose derivation context. */
    key_derivation::Aes128DerivationContext authentication_context(std::uint32_t key_number) {
        auto context = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::authentication, KeyNumber::make(key_number).value(), {}, {},
            hex("01020304"), hex("aabbccdd"));
        expect(static_cast<bool>(context), "valid authentication context fixture");
        return std::move(context.value());
    }

    /** @brief Build one validated provider request for native authentication. */
    key_derivation::KeyRequest native_request(key_derivation::AuthenticationProfile profile,
                                              std::uint32_t key_number,
                                              std::stop_token cancellation = {}) {
        auto reference = key_derivation::KeyReference::make(hex("010203"));
        expect(static_cast<bool>(reference), "valid opaque key reference fixture");
        auto request = key_derivation::KeyRequest::make(
            std::move(reference.value()), authentication_context(key_number),
            key_derivation::KeyScope::native, profile, cancellation);
        expect(static_cast<bool>(request), "valid native provider request fixture");
        return std::move(request.value());
    }

    /** @brief Build one validated provider request for ISO application authentication. */
    key_derivation::KeyRequest iso_request(std::uint32_t key_number,
                                           std::stop_token cancellation = {}) {
        auto reference = key_derivation::KeyReference::make(hex("040506"));
        expect(static_cast<bool>(reference), "valid ISO opaque key reference fixture");
        auto request = key_derivation::KeyRequest::make(
            std::move(reference.value()), authentication_context(key_number),
            key_derivation::KeyScope::iso_application,
            key_derivation::AuthenticationProfile::iso_aes, cancellation);
        expect(static_cast<bool>(request), "valid ISO provider request fixture");
        return std::move(request.value());
    }

    /** @brief Return the independent two-frame EV2 First transcript for key zero. */
    std::deque<ReplayStep> ev2_first_transcript() {
        return {
            {hex("9071000002000000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")}};
    }

    /** @brief Append the independent EV2 NonFirst transcript for key one. */
    void append_ev2_nonfirst(std::deque<ReplayStep>& steps) {
        steps.push_back({hex("90770000010100"), hex("24677DDBD46349E623798FD729006E7991AF")});
        steps.push_back(
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("42557CACA75FB489EB682F716D9123D79100")});
    }

    /** @brief Return the independent AN0945 Standard AES transcript for key zero. */
    std::deque<ReplayStep> standard_aes_transcript() {
        return {
            {hex("90AA0000010000"), hex("C5537C8EFFFCC7E152C27831AFD383BA91AF")},
            {hex("90AF0000201EF512D957973AED7E6E13991EB0FB431B373EA23400A3AC0B7749CD6FB1C32800"),
             hex("FFC212245F03DB0EA0645A495190952A9100")}};
    }

    /** @brief Return the independent three-APDU ISO AES transcript for application key two. */
    std::deque<ReplayStep> iso_aes_transcript() {
        return {{hex("0084000010"), hex("303132333435363738393a3b3c3d3e3f9000")},
                {hex("008209822007feef74e1d5036e900eee118e94929311f263c2ac89b42b2798698959a4ec86"),
                 hex("9000")},
                {hex("0088098210202122232425262728292a2b2c2d2e2f20"),
                 hex("67cabc580bbbcc1bd56aa3a168a914496e0c841e553e3bc7bcb476b580967a829000")}};
    }

    /** @brief Calculate peer response MAC from fixed public session key, explicit counter and TI.
     */
    Bytes peer_mac(CryptoProvider& crypto, Byte command, uint16_t counter, ByteView data) {
        Bytes input{
            command, static_cast<Byte>(counter), static_cast<Byte>(counter >> 8), 0x8C, 0xF1, 0x41,
            0xF3};
        append(input, data);
        auto mac = crypto.cmac(Cipher::aes128, hex("774F26743ECE6AF5033B6AE8522946F6"), input);
        expect(static_cast<bool>(mac), "peer CMAC");
        Bytes output;
        for (size_t i = 1; i < 16; i += 2) {
            output.push_back(mac.value()[i]);
        }
        return output;
    }

    /** @brief Independently encrypt and MAC one EV2 Full response for the fixed First fixture. */
    Bytes peer_full_response(CryptoProvider& crypto, std::uint16_t counter, ByteView plaintext) {
        Bytes padded(plaintext.begin(), plaintext.end());
        padded.push_back(0x80);
        padded.resize(((padded.size() + 15) / 16) * 16);
        const Bytes iv_input{0x5A,
                             0xA5,
                             0x8C,
                             0xF1,
                             0x41,
                             0xF3,
                             static_cast<Byte>(counter),
                             static_cast<Byte>(counter >> 8),
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0};
        const auto encryption_key = hex("63DC07286289A7A6C0334CA31C314A04");
        auto iv = crypto.cbc(Cipher::aes128, encryption_key, Bytes(16), iv_input, true).value();
        Bytes encrypted = crypto.cbc(Cipher::aes128, encryption_key, iv, padded, true).value();
        append(encrypted, peer_mac(crypto, 0x00, counter, encrypted));
        return encrypted;
    }

    /** @brief Independently construct the five/seven-byte wrapped APDU envelope. */
    Bytes wrap(Byte command, ByteView data) {
        Bytes r{0x90, command, 0, 0};
        if (!data.empty()) {
            r.push_back(static_cast<Byte>(data.size()));
        }
        append(r, data);
        r.push_back(0);
        return r;
    }

    /** @brief Add the wrapped native terminal status. */
    Bytes done(ByteView data) {
        Bytes r(data.begin(), data.end());
        append(r, Bytes{0x91, 0});
        return r;
    }

    /** @brief Verify managed protected chaining and NonFirst continuity from published First proof.
     */
    void secure_workflow() {
        auto base = openssl_provider().value();
        auto crypto = std::make_shared<NonceCrypto>(base);
        const auto header = hex("01000000110000");
        Bytes read_payload = header;
        append(read_payload, peer_mac(*base, 0xBD, 0, header));
        Bytes plaintext(17, 0x32);
        Bytes padded = plaintext;
        padded.push_back(0x80);
        padded.resize(32);
        // Response IV label 5AA5, fixed First TI, post-command counter1, eight trailing zeros.
        auto iv = base->cbc(Cipher::aes128, hex("63DC07286289A7A6C0334CA31C314A04"), Bytes(16),
                            hex("5AA58CF141F301000000000000000000"), true)
                      .value();
        auto encrypted =
            base->cbc(Cipher::aes128, hex("63DC07286289A7A6C0334CA31C314A04"), iv, padded, true)
                .value();
        Bytes secured_response = encrypted;
        append(secured_response, peer_mac(*base, 0, 1, encrypted));
        const auto rotated = hex("4D0787C93EE0CC8CACC8E86F16C6FEB0");
        const auto nonfirst_proof =
            base->cbc(Cipher::aes128, Bytes(16), Bytes(16), rotated, true).value();
        Bytes freemem = hex("008000");
        append(freemem, peer_mac(*base, 0, 2, hex("008000")));
        Bytes first_fragment(secured_response.begin(), secured_response.begin() + 13);
        append(first_fragment, Bytes{0x91, 0xAF});
        std::deque<ReplayStep> steps{
            {hex("9071000002000000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")},
            {wrap(0xBD, read_payload), first_fragment},
            {wrap(0xAF, {}), done(ByteView(secured_response).subspan(13))},
            {hex("90770000010100"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             done(nonfirst_proof)},
            {wrap(0x6E, peer_mac(*base, 0x6E, 1, {})), done(freemem)},
            {wrap(0x6E, peer_mac(*base, 0x6E, 2, {})), done(hex("008000"))}};
        auto reader = std::make_shared<ReplayTransport>(std::move(steps));
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key())),
               "First managed proof");
        auto read = card->read_data(FileNumber::make(1).value(), Offset::make(0).value(),
                                    ByteCount::make(17).value(), CommunicationMode::full);
        expect(read && read.value() == plaintext,
               "protected read authenticates aggregate across AF frames before decrypting");
        expect(static_cast<bool>(
                   card->authenticate_ev2_non_first_aes(KeyNumber::make(1).value(), zero_key())),
               "NonFirst proof");
        auto memory = card->free_memory();
        expect(memory && memory.value() == 32768, "NonFirst preserves counter1 for next command");
        auto tampered = card->free_memory();
        expect(!tampered && tampered.error().code == ErrorCode::integrity,
               "missing MAC is never plaintext success");
        auto blocked = card->free_memory();
        expect(!blocked && blocked.error().code == ErrorCode::session_invalid,
               "integrity failure invalidates managed session");
        expect(reader->remaining() == 0, "protected commands and AF executed exactly once");
    }

    /** @brief Verify direct and derived public First-authentication capability overloads. */
    void pcd_capability_authentication() {
        auto crypto = std::make_shared<NonceCrypto>(openssl_provider().value());
        auto reader = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("90710000050003A1A2A300"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC275944C9B56DE150BA3BD15563236A3809100")},
            {hex("9071000008000601020304050600"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC24F1764E25280F70D6BEC7DE152B871149100")},
            {hex("9071000008000601020304050600"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC24F1764E25280F70D6BEC7DE152B871149100")}});
        auto card = managed::Card::connect(reader, crypto).value();

        auto direct = card->authenticate_ev2_first_aes_with_capabilities(KeyNumber::make(0).value(),
                                                                         zero_key(), hex("A1A2A3"));
        expect(direct &&
                   direct.value().picc_capabilities ==
                       std::array<Byte, 6>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66} &&
                   direct.value().pcd_capabilities ==
                       std::array<Byte, 6>{0xA1, 0xA2, 0xA3, 0x00, 0x00, 0x00},
               "direct-key First overload returns both verified capability records");

        FixedDeriver deriver;
        const Bytes master_key(16, 0x55);
        const auto derivation_context = key_derivation::Aes128DerivationContext::make(
            key_derivation::KeyPurpose::authentication, KeyNumber::make(0).value(), {}, {},
            hex("01020304"));
        expect(static_cast<bool>(derivation_context), "valid First derivation context");
        auto derived = card->authenticate_ev2_first_aes_with_capabilities(
            aes_key(master_key), deriver, derivation_context.value(), hex("010203040506"));
        expect(derived && deriver.calls == 1 && deriver.master_key_size == 16 &&
                   deriver.diversification_size == 4 &&
                   deriver.purpose == key_derivation::KeyPurpose::authentication &&
                   deriver.key_number.value() == 0 &&
                   derived.value().pcd_capabilities == std::array<Byte, 6>{1, 2, 3, 4, 5, 6},
               "derivation First overload forwards the derived key and maximum capability record");

        FixedProvider provider;
        auto provided = card->authenticate_ev2_first_aes_with_capabilities(
            provider, native_request(key_derivation::AuthenticationProfile::ev2_first, 0),
            hex("010203040506"));
        expect(provided && provider.calls == 1 &&
                   provider.profile == key_derivation::AuthenticationProfile::ev2_first &&
                   provider.scope == key_derivation::KeyScope::native &&
                   provided.value().pcd_capabilities == std::array<Byte, 6>{1, 2, 3, 4, 5, 6},
               "provider First overload resolves once before explicit capability frames");

        auto oversized_direct = card->authenticate_ev2_first_aes_with_capabilities(
            KeyNumber::make(0).value(), zero_key(), Bytes(7));
        expect(!oversized_direct && oversized_direct.error().code == ErrorCode::invalid_argument &&
                   oversized_direct.error().outcome == Outcome::not_sent,
               "direct-key overload rejects seven capability bytes before card I/O");
        auto oversized_derived = card->authenticate_ev2_first_aes_with_capabilities(
            aes_key(master_key), deriver, derivation_context.value(), Bytes(7));
        expect(!oversized_derived &&
                   oversized_derived.error().code == ErrorCode::invalid_argument &&
                   oversized_derived.error().outcome == Outcome::not_sent && deriver.calls == 1 &&
                   reader->remaining() == 0,
               "derivation overload rejects seven capability bytes before derivation or card I/O");
    }

    /** @brief Verify both explicit GetCardUID option bytes and strict NUID response binding. */
    void card_uid_variants() {
        auto base = openssl_provider().value();
        auto crypto = std::make_shared<NonceCrypto>(base);

        Bytes without_nuid_request{0x00};
        append(without_nuid_request, peer_mac(*base, 0x51, 0, hex("00")));
        Bytes with_nuid_request{0x01};
        append(with_nuid_request, peer_mac(*base, 0x51, 1, hex("01")));
        Bytes missing_nuid_request{0x01};
        append(missing_nuid_request, peer_mac(*base, 0x51, 2, hex("01")));

        const auto uid_only = peer_full_response(*base, 1, hex("04010203040506"));
        const auto uid_and_nuid = peer_full_response(*base, 2, hex("000401020304aabbccdd"));
        const auto missing_nuid = peer_full_response(*base, 3, hex("04010203040506"));
        auto reader = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("9071000002000000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")},
            {wrap(0x51, without_nuid_request), done(uid_only)},
            {wrap(0x51, with_nuid_request), done(uid_and_nuid)},
            {wrap(0x51, missing_nuid_request), done(missing_nuid)}});
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key())),
               "GetCardUID fixture establishes AES authentication");

        auto uid = card->card_uid(CardUidRequest::without_nuid);
        expect(uid && uid.value().uid == hex("04010203040506") && !uid.value().nuid,
               "explicit option zero returns only the real UID");
        auto extended = card->card_uid(CardUidRequest::with_nuid);
        expect(extended && extended.value().uid == hex("01020304") &&
                   extended.value().nuid ==
                       std::optional<std::array<Byte, 4>>{{0xAA, 0xBB, 0xCC, 0xDD}},
               "explicit option one returns separately typed UID and NUID");
        auto truncated = card->card_uid(CardUidRequest::with_nuid);
        expect(!truncated && truncated.error().code == ErrorCode::malformed_response &&
                   truncated.error().outcome == Outcome::unknown && reader->remaining() == 0,
               "option-one response without the four-byte NUID invalidates the session");
    }

    /** @brief Verify delegated creation's mandatory AF split and protected slot operations. */
    void delegated_application_workflow() {
        auto base = openssl_provider().value();
        auto crypto = std::make_shared<NonceCrypto>(base);
        const auto metadata = hex("56341202010305040f81");
        const auto encrypted_key =
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const auto dam_mac = hex("a0a1a2a3a4a5a6a7");
        Bytes authorization = encrypted_key;
        append(authorization, dam_mac);
        Bytes complete = metadata;
        append(complete, authorization);
        Bytes continuation = authorization;
        append(continuation, peer_mac(*base, 0xC9, 0, complete));

        const auto info_payload = hex("0734127856563412");
        Bytes info_request = hex("3412");
        append(info_request, peer_mac(*base, 0x69, 1, hex("3412")));
        Bytes info_response = info_payload;
        append(info_response, peer_mac(*base, 0, 2, info_payload));

        Bytes delete_payload = hex("563412a0a1a2a3a4a5a6a7");
        append(delete_payload, peer_mac(*base, 0xDA, 2, hex("563412a0a1a2a3a4a5a6a7")));

        std::deque<ReplayStep> steps{
            {hex("9071000002100000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")},
            {wrap(0xC9, metadata), hex("91af")},
            {wrap(0xAF, continuation), done(peer_mac(*base, 0, 1, {}))},
            {wrap(0x69, info_request), done(info_response)},
            {wrap(0xDA, delete_payload), done(peer_mac(*base, 0, 3, {}))}};
        auto reader = std::make_shared<ReplayTransport>(std::move(steps));
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0x10).value(), zero_key())),
               "delegated workflow establishes AES authentication");
        DelegatedApplicationConfiguration delegated{
            ApplicationConfiguration{ApplicationId::make(0x123456).value()}, 0x0102, 0x03, 0x0405};
        expect(static_cast<bool>(
                   card->create_delegated_application(delegated, encrypted_key, dam_mac)),
               "delegated creation verifies its final protected response");
        auto info = card->delegated_application_info(0x1234);
        expect(info && info.value().application.value() == 0x123456 &&
                   info.value().free_blocks == 0x5678,
               "managed delegated information is strictly decoded");
        expect(static_cast<bool>(card->delete_delegated_application(
                   ApplicationId::make(0x123456).value(), dam_mac)),
               "delegated deletion verifies its protected acknowledgement");
        expect(reader->remaining() == 0,
               "delegated operations use the exact authenticated wire transcript");
    }

    /** @brief Reject DAM creation outside the tracked PICC selection before any C9 frame. */
    void delegated_application_requires_picc_selection() {
        auto crypto = std::make_shared<NonceCrypto>(openssl_provider().value());
        auto reader = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("905a00000356341200"), hex("9100")},
            {hex("9071000002100000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")}});
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(card->select_application(ApplicationId::make(0x123456).value())),
               "non-PICC selection fixture succeeds");
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0x10).value(), zero_key())),
               "DAM selector authentication fixture succeeds");
        DelegatedApplicationConfiguration delegated{
            ApplicationConfiguration{ApplicationId::make(0x654321).value()}, 0, 0, 0x40};
        auto rejected = card->create_delegated_application(delegated, Bytes(32), Bytes(8));
        expect(!rejected && rejected.error().code == ErrorCode::authentication &&
                   rejected.error().outcome == Outcome::not_sent && reader->remaining() == 0,
               "delegated creation requires tracked PICC selection before I/O");
    }

    /** @brief ResetAuthentication blocks ordinary I/O until an explicit resynchronization. */
    void reset_authentication_keeps_connection() {
        auto crypto = std::make_shared<NonceCrypto>(openssl_provider().value());
        auto reader = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("9071000002000000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")},
            {hex("905a00000300000000"), hex("9100")},
            {hex("906e000000"), hex("0080009100")}});
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key())),
               "reset-authentication fixture establishes AES authentication");
        expect(static_cast<bool>(card->reset_authentication()),
               "local authentication state is erased without transport reset");
        auto nonfirst =
            card->authenticate_ev2_non_first_aes(KeyNumber::make(1).value(), zero_key());
        expect(!nonfirst && nonfirst.error().code == ErrorCode::session_invalid,
               "NonFirst cannot use erased authentication state");
        auto blocked = card->free_memory();
        expect(!blocked && blocked.error().code == ErrorCode::session_invalid &&
                   blocked.error().outcome == Outcome::not_sent,
               "ordinary I/O is blocked while host and card authentication can differ");
        auto blocked_names = card->df_names();
        expect(!blocked_names && blocked_names.error().code == ErrorCode::session_invalid &&
                   blocked_names.error().outcome == Outcome::not_sent,
               "GetDFNames cannot bypass the local authentication-reset recovery gate");
        expect(static_cast<bool>(card->select_application(ApplicationId::make(0).value())),
               "application selection re-synchronizes card and host authentication state");
        auto memory = card->free_memory();
        expect(memory && memory.value() == 32768 && reader->remaining() == 0,
               "plain command resumes after explicit authentication reset on the card");
    }

    /** @brief A local protection failure cannot resurrect an invalid session via NonFirst. */
    void failed_preparation_blocks_nonfirst() {
        auto base = openssl_provider().value();
        auto crypto = std::make_shared<NonceCrypto>(base);
        Bytes memory = hex("008000");
        append(memory, peer_mac(*base, 0, 1, hex("008000")));
        auto reader = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("9071000002000000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")},
            {wrap(0x6E, peer_mac(*base, 0x6E, 0, {})), done(memory)}});
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key())),
               "setup authenticated session");
        expect(static_cast<bool>(card->free_memory()),
               "advance secure counter before local failure");
        crypto->fail_cmac = true;
        auto failed = card->free_memory();
        expect(!failed && failed.error().code == ErrorCode::crypto, "local MAC failure returned");
        crypto->fail_cmac = false;
        auto forbidden =
            card->authenticate_ev2_non_first_aes(KeyNumber::make(1).value(), zero_key());
        expect(!forbidden && forbidden.error().code == ErrorCode::session_invalid &&
                   reader->remaining() == 0,
               "NonFirst cannot revive invalidated keys or counter");
    }

    /** @brief A reconnect after challenge must never receive the old card's authentication proof.
     */
    void generation_change_stops_handshake() {
        auto crypto = std::make_shared<NonceCrypto>(openssl_provider().value());
        std::shared_ptr<CallbackTransport> reader;
        std::size_t exchanges = 0;
        TransportCallbacks callbacks;
        callbacks.exchange = [&](ByteView request, const ExchangeOptions&) -> Result<Bytes> {
            ++exchanges;
            expect(std::ranges::equal(request, hex("9071000002000000")),
                   "only First challenge request may reach reader");
            reader->notify_state_change();
            return hex("24677DDBD46349E623798FD729006E7991AF");
        };
        reader = std::make_shared<CallbackTransport>(TransportCapabilities{}, std::move(callbacks));
        auto card = managed::Card::connect(reader, crypto).value();
        auto result = card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key());
        expect(!result && result.error().code == ErrorCode::card_removed &&
                   result.error().outcome == Outcome::unknown,
               "changed connection returns uncertain removal evidence");
        expect(exchanges == 1, "AF proof is not sent after reader generation changes");
        auto blocked = card->free_memory();
        expect(!blocked && blocked.error().code == ErrorCode::session_invalid,
               "changed authentication connection stays unusable");
    }

    /** @brief Key-change trust derives from actual authentication, and DF-name exceptions erase it.
     */
    void trusted_selector_and_provider_exception() {
        auto crypto = std::make_shared<NonceCrypto>(openssl_provider().value());
        auto reader = std::make_shared<ReplayTransport>(std::deque<ReplayStep>{
            {hex("9071000002000000"), hex("24677DDBD46349E623798FD729006E7991AF")},
            {hex("90AF0000203B50445F21D21D77D500794DEB245E5A754F5F901844259F4C9B31A5C7335ACD00"),
             hex("04C6DBD67417ED0D31DDDE4D2E3FFAC2B4B074F638EEF7FFF9254963B65C77599100")}});
        auto card = managed::Card::connect(reader, crypto).value();
        expect(static_cast<bool>(
                   card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key())),
               "establish key-zero trust");
        auto change =
            change_aes_key(KeyNumber::make(1).value(), Bytes(16), 1, KeyNumber::make(1).value());
        expect(static_cast<bool>(change), "structurally valid current-key change fixture");
        auto rejected = card->execute(change.value());
        expect(!rejected && rejected.error().code == ErrorCode::authentication &&
                   reader->remaining() == 0,
               "caller cannot invent the authenticated key selector to bypass response MAC");
        auto names = card->df_names();
        expect(!names && names.error().code == ErrorCode::authentication &&
                   names.error().outcome == Outcome::not_sent && reader->remaining() == 0,
               "GetDFNames is blocked before I/O while AES authentication is active");
        crypto->throw_cmac = true;
        auto failed = card->free_memory();
        expect(!failed && failed.error().code == ErrorCode::internal,
               "authenticated command crypto exception is contained");
        crypto->throw_cmac = false;
        auto forbidden =
            card->authenticate_ev2_non_first_aes(KeyNumber::make(1).value(), zero_key());
        expect(!forbidden && forbidden.error().code == ErrorCode::session_invalid,
               "exception cannot leave revivable security state");
    }

    /** @brief Exercise Direct, Derived, and Provider paths for every managed AES auth family. */
    void authentication_key_source_matrix() {
        const auto base = openssl_provider().value();
        constexpr std::size_t direct = 0;
        constexpr std::size_t derived = 1;
        constexpr std::size_t provided = 2;

        for (std::size_t source = direct; source <= provided; ++source) {
            auto crypto =
                std::make_shared<NonceCrypto>(base, hex("2347C1557F80707ABDFF86BF9D965CA7"));
            auto reader = std::make_shared<ReplayTransport>(standard_aes_transcript());
            auto card = managed::Card::connect(reader, crypto).value();
            Result<void> result = invalid("unselected Standard AES source");
            FixedDeriver deriver;
            FixedProvider provider;
            if (source == direct) {
                result = card->authenticate_standard_aes(KeyNumber::make(0).value(), zero_key());
            } else if (source == derived) {
                result =
                    card->authenticate_standard_aes(zero_key(), deriver, authentication_context(0));
            } else {
                result = card->authenticate_standard_aes(
                    provider,
                    native_request(key_derivation::AuthenticationProfile::standard_aes, 0));
            }
            expect(result && reader->remaining() == 0 &&
                       deriver.calls == (source == derived ? 1U : 0U) &&
                       provider.calls == (source == provided ? 1U : 0U) &&
                       (source != derived ||
                        (deriver.master_key_size == 16 && deriver.diversification_size == 4 &&
                         deriver.purpose == key_derivation::KeyPurpose::authentication &&
                         deriver.key_number.value() == 0)) &&
                       (source != provided ||
                        (provider.profile == key_derivation::AuthenticationProfile::standard_aes &&
                         provider.scope == key_derivation::KeyScope::native)),
                   "Standard AES Direct/Derived/Provider path sends one exact transcript");
        }

        for (std::size_t source = direct; source <= provided; ++source) {
            auto crypto = std::make_shared<NonceCrypto>(base);
            auto reader = std::make_shared<ReplayTransport>(ev2_first_transcript());
            auto card = managed::Card::connect(reader, crypto).value();
            Result<model::AuthenticationInfo> result = invalid("unselected EV2 First source");
            FixedDeriver deriver;
            FixedProvider provider;
            if (source == direct) {
                result = card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key());
            } else if (source == derived) {
                result = card->authenticate_ev2_first_aes(zero_key(), deriver,
                                                          authentication_context(0));
            } else {
                result = card->authenticate_ev2_first_aes(
                    provider, native_request(key_derivation::AuthenticationProfile::ev2_first, 0));
            }
            expect(result && reader->remaining() == 0 &&
                       deriver.calls == (source == derived ? 1U : 0U) &&
                       provider.calls == (source == provided ? 1U : 0U) &&
                       (source != derived ||
                        (deriver.master_key_size == 16 && deriver.diversification_size == 4 &&
                         deriver.purpose == key_derivation::KeyPurpose::authentication &&
                         deriver.key_number.value() == 0)) &&
                       (source != provided ||
                        (provider.profile == key_derivation::AuthenticationProfile::ev2_first &&
                         provider.scope == key_derivation::KeyScope::native)),
                   "EV2 First Direct/Derived/Provider path sends one exact transcript");
        }

        for (std::size_t source = direct; source <= provided; ++source) {
            auto crypto = std::make_shared<NonceCrypto>(base);
            auto steps = ev2_first_transcript();
            append_ev2_nonfirst(steps);
            auto reader = std::make_shared<ReplayTransport>(std::move(steps));
            auto card = managed::Card::connect(reader, crypto).value();
            expect(static_cast<bool>(
                       card->authenticate_ev2_first_aes(KeyNumber::make(0).value(), zero_key())),
                   "EV2 NonFirst source fixture establishes First state");
            Result<model::AuthenticationInfo> result = invalid("unselected NonFirst source");
            FixedDeriver deriver;
            FixedProvider provider;
            if (source == direct) {
                result =
                    card->authenticate_ev2_non_first_aes(KeyNumber::make(1).value(), zero_key());
            } else if (source == derived) {
                result = card->authenticate_ev2_non_first_aes(zero_key(), deriver,
                                                              authentication_context(1));
            } else {
                result = card->authenticate_ev2_non_first_aes(
                    provider,
                    native_request(key_derivation::AuthenticationProfile::ev2_non_first, 1));
            }
            expect(result && reader->remaining() == 0 &&
                       deriver.calls == (source == derived ? 1U : 0U) &&
                       provider.calls == (source == provided ? 1U : 0U) &&
                       (source != derived ||
                        (deriver.master_key_size == 16 && deriver.diversification_size == 4 &&
                         deriver.purpose == key_derivation::KeyPurpose::authentication &&
                         deriver.key_number.value() == 1)) &&
                       (source != provided ||
                        (provider.profile == key_derivation::AuthenticationProfile::ev2_non_first &&
                         provider.scope == key_derivation::KeyScope::native)),
                   "EV2 NonFirst Direct/Derived/Provider path sends one exact transcript");
        }

        const Bytes iso_key = hex("000102030405060708090a0b0c0d0e0f");
        for (std::size_t source = direct; source <= provided; ++source) {
            auto crypto = std::make_shared<NonceCrypto>(
                base, hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"));
            auto reader = std::make_shared<ReplayTransport>(iso_aes_transcript());
            auto card = managed::Card::connect(reader, crypto).value();
            const auto key_reference = iso7816::checked::KeyReference::application(2).value();
            Result<void> result = invalid("unselected ISO AES source");
            FixedDeriver deriver(iso_key);
            FixedProvider provider(iso_key);
            if (source == direct) {
                result = card->authenticate_iso_aes(key_reference, aes_key(iso_key));
            } else if (source == derived) {
                result = card->authenticate_iso_aes(key_reference, zero_key(), deriver,
                                                    authentication_context(2));
            } else {
                result = card->authenticate_iso_aes(key_reference, provider, iso_request(2));
            }
            expect(result && reader->remaining() == 0 &&
                       deriver.calls == (source == derived ? 1U : 0U) &&
                       provider.calls == (source == provided ? 1U : 0U) &&
                       (source != derived ||
                        (deriver.master_key_size == 16 && deriver.diversification_size == 4 &&
                         deriver.purpose == key_derivation::KeyPurpose::authentication &&
                         deriver.key_number.value() == 2)) &&
                       (source != provided ||
                        (provider.profile == key_derivation::AuthenticationProfile::iso_aes &&
                         provider.scope == key_derivation::KeyScope::iso_application)),
                   "ISO AES Direct/Derived/Provider path sends one exact transcript");
        }
    }

    /** @brief Prove provider failures, cancellation, exceptions, and reentry stay before card I/O.
     */
    void provider_failure_boundaries() {
        auto crypto = std::make_shared<NonceCrypto>(openssl_provider().value());
        std::size_t exchanges{};
        auto transport = std::make_shared<CallbackTransport>(
            TransportCapabilities{},
            TransportCallbacks{.exchange = [&](ByteView, const ExchangeOptions&) -> Result<Bytes> {
                                   ++exchanges;
                                   return Error{ErrorCode::internal,
                                                "unexpected provider-boundary card I/O"};
                               },
                               .cancel = {},
                               .reset = {}});
        auto card = managed::Card::connect(transport, crypto).value();

        FixedProvider failed(Bytes(16), FixedProvider::Behavior::failure);
        auto failure = card->authenticate_standard_aes(
            failed, native_request(key_derivation::AuthenticationProfile::standard_aes, 0));
        expect(!failure && failure.error().code == ErrorCode::crypto &&
                   failure.error().outcome == Outcome::not_sent &&
                   failure.error().device_status == 0 &&
                   failure.error().message == "AES-128 key provider failed" && failed.calls == 1 &&
                   exchanges == 0,
               "provider failure is redacted and remains not-sent with zero card I/O");

        FixedProvider throwing(Bytes(16), FixedProvider::Behavior::exception);
        auto exception = card->authenticate_standard_aes(
            throwing, native_request(key_derivation::AuthenticationProfile::standard_aes, 0));
        expect(!exception && exception.error().code == ErrorCode::internal &&
                   exception.error().outcome == Outcome::not_sent && throwing.calls == 1 &&
                   exchanges == 0,
               "provider exception is contained before card I/O");

        FixedProvider moved(Bytes(16), FixedProvider::Behavior::moved_from);
        auto invalid_key = card->authenticate_standard_aes(
            moved, native_request(key_derivation::AuthenticationProfile::standard_aes, 0));
        expect(!invalid_key && invalid_key.error().code == ErrorCode::crypto &&
                   invalid_key.error().outcome == Outcome::not_sent && moved.calls == 1 &&
                   exchanges == 0,
               "provider moved-from key is rejected before card I/O");

        std::stop_source already_cancelled;
        already_cancelled.request_stop();
        FixedProvider skipped;
        auto cancelled = card->authenticate_standard_aes(
            skipped, native_request(key_derivation::AuthenticationProfile::standard_aes, 0,
                                    already_cancelled.get_token()));
        expect(!cancelled && cancelled.error().code == ErrorCode::cancelled &&
                   cancelled.error().outcome == Outcome::not_sent && skipped.calls == 0 &&
                   exchanges == 0,
               "pre-cancelled provider request is never invoked and sends no frame");

        std::stop_source during;
        FixedProvider cancelled_during;
        cancelled_during.during_resolution = [&](const key_derivation::KeyRequest&) {
            during.request_stop();
        };
        auto interrupted = card->authenticate_standard_aes(
            cancelled_during, native_request(key_derivation::AuthenticationProfile::standard_aes, 0,
                                             during.get_token()));
        expect(!interrupted && interrupted.error().code == ErrorCode::cancelled &&
                   interrupted.error().outcome == Outcome::not_sent &&
                   cancelled_during.calls == 1 && cancelled_during.saw_cancellation &&
                   exchanges == 0,
               "cancellation raised during provider resolution suppresses card I/O");

        std::stop_source operation_stop;
        FixedProvider operation_cancelled;
        operation_cancelled.during_resolution = [&](const key_derivation::KeyRequest&) {
            operation_stop.request_stop();
        };
        ExchangeOptions operation_options{};
        operation_options.stop = operation_stop.get_token();
        auto operation_interrupted = card->authenticate_standard_aes(
            operation_cancelled,
            native_request(key_derivation::AuthenticationProfile::standard_aes, 0),
            operation_options);
        expect(!operation_interrupted &&
                   operation_interrupted.error().code == ErrorCode::cancelled &&
                   operation_interrupted.error().outcome == Outcome::not_sent &&
                   operation_cancelled.calls == 1 && operation_cancelled.saw_cancellation &&
                   exchanges == 0,
               "operation cancellation during provider resolution suppresses card I/O");

        FixedProvider wrong_profile;
        auto mismatch = card->authenticate_standard_aes(
            wrong_profile, native_request(key_derivation::AuthenticationProfile::ev2_first, 0));
        expect(!mismatch && mismatch.error().code == ErrorCode::invalid_argument &&
                   mismatch.error().outcome == Outcome::not_sent && wrong_profile.calls == 0 &&
                   exchanges == 0,
               "profile mismatch is rejected before provider invocation or card I/O");

        auto replay = std::make_shared<ReplayTransport>(standard_aes_transcript());
        auto standard_crypto = std::make_shared<NonceCrypto>(
            openssl_provider().value(), hex("2347C1557F80707ABDFF86BF9D965CA7"));
        auto reentrant_card = managed::Card::connect(replay, standard_crypto).value();
        FixedProvider reentrant;
        bool saw_busy{};
        reentrant.during_resolution = [&](const key_derivation::KeyRequest&) {
            auto nested = reentrant_card->free_memory();
            saw_busy = !nested && nested.error().code == ErrorCode::busy &&
                       nested.error().outcome == Outcome::not_sent;
        };
        auto outer = reentrant_card->authenticate_standard_aes(
            reentrant, native_request(key_derivation::AuthenticationProfile::standard_aes, 0));
        expect(outer && saw_busy && reentrant.calls == 1 && replay->remaining() == 0,
               "provider callback reentry is busy while outer authentication completes once");
    }

} // namespace

/** @brief Run the managed security integration regression. */
int main() {
    secure_workflow();
    pcd_capability_authentication();
    card_uid_variants();
    delegated_application_workflow();
    delegated_application_requires_picc_selection();
    reset_authentication_keeps_connection();
    failed_preparation_blocks_nonfirst();
    generation_change_stops_handshake();
    trusted_selector_and_provider_exception();
    authentication_key_source_matrix();
    provider_failure_boundaries();
    std::cout << "Managed EV3 session tests passed\n";
}
