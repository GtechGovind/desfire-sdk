/**
 * @file ev3_iso7816_test.cpp
 * @brief Independent ISO APDU transcripts, retained-CMAC vectors, and failure boundaries.
 */
#include <desfire/ev3/iso7816/checked/channel.hpp>
#include <desfire/ev3/iso7816/raw/codec.hpp>
#include <desfire/ev3/iso7816/security/aes/session.hpp>
#include <desfire/transports/replay.hpp>

#include <cstdlib>
#include <deque>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
    namespace aes = desfire::ev3::iso7816::security::aes;
    namespace checked = desfire::ev3::iso7816::checked;
    namespace raw = desfire::ev3::iso7816::raw;

    using namespace desfire;
    using namespace checked;
    using namespace desfire::transports;

    /** @brief Stop on a failed observable invariant without printing sensitive fixture data. */
    void expect(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(EXIT_FAILURE);
        }
    }

    /** @brief Decode an independently specified non-production fixture. */
    Bytes hex(std::string_view value) {
        auto result = from_hex(value);
        expect(static_cast<bool>(result), "hex fixture is valid");
        return std::move(result.value());
    }

    /** @brief Compare spans without depending on a C++ library span comparison extension. */
    bool same(ByteView left, ByteView right) {
        return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin());
    }

    /** @brief Own one replay transport through raw and checked ISO channel layers. */
    class IsoFixture final {
    public:

        /** @brief Create an exclusively owning channel around an independent wire transcript. */
        explicit IsoFixture(std::deque<ReplayStep> steps, TransportCapabilities capabilities = {}) {
            auto transport = std::make_shared<ReplayTransport>(std::move(steps), capabilities);
            replay_ = transport.get();
            auto channel = raw::Channel::create(std::move(transport));
            expect(static_cast<bool>(channel), "raw ISO fixture channel");
            raw_ = std::move(channel.value());
            checked_ = std::make_unique<checked::Channel>(*raw_);
        }

        /** @brief Execute one semantic ISO command through both channel layers. */
        Result<checked::Response> exchange(const checked::Command& command,
                                           const ExchangeOptions& options = {},
                                           const checked::Limits& limits = {}) {
            return checked_->exchange(command, options, limits);
        }

        /** @brief Borrow the stable checked channel for ISO AES authentication and messaging. */
        checked::Channel& channel() noexcept {
            return *checked_;
        }

        /** @brief Reset the exclusively owned replay transport through the raw channel. */
        Result<void> reset() {
            return raw_->reset();
        }

        /** @brief Count unconsumed independent wire expectations. */
        std::size_t remaining() const {
            return replay_->remaining();
        }

    private:

        ReplayTransport* replay_{};
        std::unique_ptr<raw::Channel> raw_;
        std::unique_ptr<checked::Channel> checked_;
    };

    /** @brief Build a validated byte address for fixtures that use the currently selected EF. */
    BinaryAddress address(std::uint32_t offset = 0) {
        auto result = BinaryAddress::current_file(offset);
        expect(static_cast<bool>(result), "fixture offset is valid");
        return result.value();
    }

    /** @brief Check one complete APDU against a literal, independent of the production encoder. */
    void expect_frame(Result<Command> command, std::string_view expected) {
        expect(static_cast<bool>(command), "fixture command is valid");
        auto encoded = raw::encode(command.value().apdu());
        expect(encoded && encoded.value() == hex(expected),
               "ISO APDU matches independent wire literal");
    }

    /** @brief Cover CLA, endian order, P1/P2 selectors, APDU cases, and zero-coded Le boundaries.
     */
    void check_encoding() {
        expect_frame(Command::select_file(0x3F00), "00a40000023f0000");
        expect_frame(
            Command::select_file(0xE103, FileSelection::elementary_file, SelectionResponse::none),
            "00a4020c02e103");
        expect_frame(Command::select_file(0x1234, FileSelection::child_df, SelectionResponse::fci,
                                          LengthEncoding::extended),
                     "00a4010000000212340000");
        expect_frame(Command::select_df_name(hex("d2760000850101")), "00a4040007d276000085010100");
        expect_frame(Command::read_binary(address(0x1234), 256), "00b0123400");
        expect_frame(Command::read_binary(address(), 65536), "00b00000000000");
        expect_frame(Command::read_binary(address(), 256, LengthEncoding::extended),
                     "00b00000000100");
        auto short_address = BinaryAddress::short_file(0x1F, 0xFF);
        expect_frame(Command::read_binary(short_address.value(), 1), "00b09fff01");
        expect_frame(Command::update_binary(address(0x1234), hex("010203")), "00d6123403010203");
        expect_frame(Command::update_binary(address(), hex("0102"), LengthEncoding::extended),
                     "00d600000000020102");
        expect_frame(Command::read_records(2, 3, RecordSelection::one, 16), "00b2021c10");
        expect_frame(Command::read_records(0, 0, RecordSelection::from_record, 65536),
                     "00b20005000000");
        expect_frame(Command::append_record(3, hex("aabb")), "00e2001802aabb");
        expect_frame(Command::update_record(UpdateRecordInstruction::dc, 2, 3, 5, hex("aabbcc")),
                     "00dc021d03aabbcc");
        expect_frame(Command::update_record(UpdateRecordInstruction::dd, 0, 0, 4, hex("aa")),
                     "00dd000401aa");
        expect_frame(Command::get_challenge(), "0084000010");
        expect_frame(Command::get_challenge(8, LengthEncoding::extended), "00840000000008");
        const auto key = KeyReference::application(13).value();
        expect_frame(Command::external_authenticate(Algorithm::tdes2, key,
                                                    hex("000102030405060708090a0b0c0d0e0f")),
                     "0082028d10000102030405060708090a0b0c0d0e0f");
        expect_frame(Command::internal_authenticate(Algorithm::aes128, KeyReference::picc_master(),
                                                    hex("000102030405060708090a0b0c0d0e0f")),
                     "0088090010000102030405060708090a0b0c0d0e0f20");
    }

    /** @brief Reject narrowing, reserved selector values, and impossible authentication lengths. */
    void check_validation() {
        expect(!BinaryAddress::current_file(0x8000), "fifteen-bit offset rejects overflow");
        expect(!BinaryAddress::short_file(32, 0), "short identifier rejects overflow");
        expect(!BinaryAddress::short_file(1, 256), "short offset rejects overflow");
        expect(!KeyReference::application(14), "ISO application key count is bounded");
        expect(!Command::select_file(65536), "FID rejects overflow");
        expect(!Command::select_file(0, static_cast<FileSelection>(4)),
               "invalid FID selector rejected");
        expect(!Command::select_df_name({}), "empty DF name rejected");
        expect(!Command::select_df_name(Bytes(17)), "long DF name rejected");
        expect(!Command::read_binary(address(), 0), "zero host Le is not silently reinterpreted");
        expect(!Command::read_binary(address(), 65537), "extended Le overflow rejected");
        expect(!Command::read_binary(address(), 257, LengthEncoding::short_apdu),
               "short Le overflow rejected");
        expect(!Command::read_binary(address(), 1, static_cast<LengthEncoding>(9)),
               "invalid length mode rejected");
        expect(!Command::update_binary(address(), {}), "zero Lc update rejected");
        expect(!Command::update_binary(address(), Bytes(65536)), "extended Lc overflow rejected");
        expect(!Command::read_records(256, 0, RecordSelection::one, 1),
               "record index overflow rejected");
        expect(!Command::append_record(32, hex("00")), "append identifier overflow rejected");
        expect(!Command::update_record(UpdateRecordInstruction::dc, 256, 0, 0, hex("00")),
               "update-record number overflow rejected");
        expect(!Command::update_record(UpdateRecordInstruction::dc, 0, 32, 0, hex("00")),
               "update-record short identifier overflow rejected");
        expect(!Command::update_record(UpdateRecordInstruction::dc, 0, 0, 8, hex("00")),
               "update-record control bits cannot overlap the short identifier");
        expect(!Command::update_record(UpdateRecordInstruction::dc, 0, 0, 0, {}),
               "empty update-record data rejected");
        expect(!Command::update_record(UpdateRecordInstruction::dc, 0, 0, 0, Bytes(256)),
               "documented short update-record length is bounded");
        expect(!Command::update_record(static_cast<UpdateRecordInstruction>(0), 0, 0, 0, hex("00")),
               "unknown update-record instruction rejected");
        expect(!Command::get_challenge(15), "challenge length checked");
        expect(!Command::external_authenticate(Algorithm::aes128, KeyReference::picc_master(),
                                               Bytes(16)),
               "AES external proof must have two sixteen-byte random values");
        expect(!Command::internal_authenticate(static_cast<Algorithm>(3),
                                               KeyReference::picc_master(), Bytes(16)),
               "unknown authentication algorithm rejected");
        expect(Command::select_file(0).value().resets_authentication(),
               "application selection erases authentication");
        expect(!Command::select_file(0, FileSelection::elementary_file)
                    .value()
                    .resets_authentication(),
               "elementary-file selection preserves authentication");
        auto large = Command::update_binary(address(), Bytes(65535, 0xA5));
        auto encoded = raw::encode(large.value().apdu());
        expect(encoded && encoded.value().size() == 65542 && encoded.value()[4] == 0 &&
                   encoded.value()[5] == 0xFF && encoded.value()[6] == 0xFF,
               "maximum Lc is encoded without truncation");
    }

    /** @brief Preserve warnings and native-looking status words without misreporting success. */
    void check_status_and_continuation() {
        expect(!raw::decode({}), "empty ISO response rejected");
        expect(!raw::decode(hex("90")), "one-byte ISO response rejected");
        auto warning = raw::decode(hex("aabb6282"));
        expect(warning && !warning.value().success() && warning.value().status == 0x6282 &&
                   warning.value().data == hex("aabb"),
               "ISO warning retains payload and status");
        auto native_status = raw::decode(hex("9100"));
        expect(native_status && !native_status.value().success(),
               "91xx never treated as ISO success");
        IsoFixture chained(
            {{hex("00b0000004"), hex("01026102")}, {hex("00c0000002"), hex("03049000")}});
        auto result = chained.exchange(Command::read_binary(address(), 4).value());
        expect(result && result.value() == Response{0x9000, hex("01020304")} &&
                   chained.remaining() == 0,
               "61xx is followed by GET RESPONSE and concatenated once");
        IsoFixture zero_length(
            {{hex("00b0000001"), hex("6100")}, {hex("00c0000000"), hex("079000")}});
        result = zero_length.exchange(Command::read_binary(address(), 1).value());
        expect(result && result.value().data == hex("07") && zero_length.remaining() == 0,
               "6100 requests the ISO short maximum using zero Le");
        IsoFixture warning_end(
            {{hex("00b0000004"), hex("01026102")}, {hex("00c0000002"), hex("036282")}});
        result = warning_end.exchange(Command::read_binary(address(), 4).value());
        expect(result && result.value() == Response{0x6282, hex("010203")},
               "terminal warnings preserve aggregated bytes without claiming success");
    }

    /** @brief Restrict 6Cxx correction to one initial unauthenticated data read. */
    void check_length_correction() {
        IsoFixture corrected(
            {{hex("00b0000001"), hex("6c02")}, {hex("00b0000002"), hex("aabb9000")}});
        auto result = corrected.exchange(Command::read_binary(address(), 1).value());
        expect(result && result.value().data == hex("aabb") && corrected.remaining() == 0,
               "read retries once with card-reported Le");
        IsoFixture repeated({{hex("00b0000001"), hex("6c02")}, {hex("00b0000002"), hex("6c03")}});
        result = repeated.exchange(Command::read_binary(address(), 1).value());
        expect(result && result.value().status == 0x6C03 && repeated.remaining() == 0,
               "second length rejection is returned without a third transmission");
        IsoFixture mutation({{hex("00d6000001aa"), hex("6c02")}});
        result = mutation.exchange(Command::update_binary(address(), hex("aa")).value());
        expect(result && result.value().status == 0x6C02 && mutation.remaining() == 0,
               "mutation is never retried for 6Cxx");
        IsoFixture auth({{hex("0084000010"), hex("6c08")}});
        result = auth.exchange(Command::get_challenge().value());
        expect(result && result.value().status == 0x6C08,
               "challenge is never regenerated by correction");
        IsoFixture selection({{hex("00a40000023f0000"), hex("6c02")}});
        result = selection.exchange(Command::select_file(0x3F00).value());
        expect(result && result.value().status == 0x6C02,
               "selection is never repeated by correction");
        IsoFixture continuation(
            {{hex("00b0000002"), hex("aa6101")}, {hex("00c0000001"), hex("6c02")}});
        result = continuation.exchange(Command::read_binary(address(), 2).value());
        expect(result && result.value() == Response{0x6C02, hex("aa")},
               "GET RESPONSE is not replayed when a continuation is rejected");
        IsoFixture malformed_length({{hex("00b0000001"), hex("aa6c02")}});
        result = malformed_length.exchange(Command::read_binary(address(), 1).value());
        expect(!result && result.error().code == ErrorCode::malformed_response,
               "length rejection carrying data is malformed");
    }

    /** @brief Bound malicious continuations and preserve partial-delivery uncertainty. */
    void check_exchange_bounds() {
        auto read = Command::read_binary(address(), 2).value();
        IsoFixture bytes({{hex("00b0000002"), hex("01026101")}});
        auto result = bytes.exchange(read, {}, Limits{2, 4, true});
        expect(!result && result.error().outcome == Outcome::unknown && bytes.remaining() == 0,
               "byte limit stops continuation before an oversized download");
        IsoFixture frames({{hex("00b0000002"), hex("6101")}, {hex("00c0000001"), hex("6101")}});
        result = frames.exchange(read, {}, Limits{10, 2, true});
        expect(!result && result.error().code == ErrorCode::malformed_response &&
                   frames.remaining() == 0,
               "empty endless continuations hit a hard frame limit");
        IsoFixture interrupted(
            {{hex("00b0000002"), hex("016101")},
             {hex("00c0000001"), Error{ErrorCode::timeout, "fixture", Outcome::not_sent}}});
        result = interrupted.exchange(read);
        expect(!result && result.error().outcome == Outcome::unknown,
               "continuation not-sent failure cannot make logical delivery not-sent");
        TransportCapabilities native_caps;
        native_caps.framing = Framing::native;
        IsoFixture native({}, native_caps);
        result = native.exchange(read);
        expect(!result && result.error().code == ErrorCode::unsupported &&
                   result.error().outcome == Outcome::not_sent,
               "actual ISO does not pass through native framing");
        TransportCapabilities tiny_caps;
        tiny_caps.max_transmit = 4;
        IsoFixture tiny({}, tiny_caps);
        result = tiny.exchange(read);
        expect(!result && result.error().outcome == Outcome::not_sent,
               "transport capacity checked before I/O");
        IsoFixture idle({});
        std::stop_source stop;
        stop.request_stop();
        result =
            idle.exchange(read, ExchangeOptions{std::chrono::milliseconds(50), stop.get_token()});
        expect(!result && result.error().code == ErrorCode::cancelled &&
                   result.error().outcome == Outcome::not_sent,
               "pre-cancelled ISO exchange sends no frame");
        result = idle.exchange(read, ExchangeOptions{std::chrono::milliseconds(0), {}});
        expect(!result && result.error().code == ErrorCode::invalid_argument,
               "nonpositive timeout rejected");
    }

    /** @brief Independent primitive invocation and answer, generated with Python cryptography AES.
     */
    struct CipherStep {
        Bytes key;
        Bytes iv;
        Bytes input;
        bool encrypt;
        Bytes output;
    };

    /** @brief Fixture provider verifies every primitive input against independent known answers. */
    class VectorCrypto final : public CryptoProvider {
    public:

        Bytes random_bytes{hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")};
        std::deque<CipherStep> steps;
        bool throw_random{};
        bool throw_cbc{};

        /** @brief Return fixed non-production randomness, checking the requested width. */
        Result<Bytes> random(std::size_t size) override {
            expect(size == 32, "mutual ISO auth requests independent random values together");
            if (throw_random) {
                throw std::runtime_error("injected random exception");
            }
            return random_bytes;
        }

        /** @brief Match key, retained IV, complete input, and AES direction before releasing a
         * vector. */
        Result<Bytes> cbc(Cipher cipher, ByteView key, ByteView iv, ByteView input,
                          bool encrypt) override {
            if (throw_cbc) {
                throw std::runtime_error("injected CBC exception");
            }
            expect(!steps.empty(), "unexpected crypto operation is rejected");
            const auto& step = steps.front();
            expect(cipher == Cipher::aes128 && same(key, step.key) && same(iv, step.iv) &&
                       same(input, step.input) && encrypt == step.encrypt,
                   "AES operation matches an independent vector");
            auto result = step.output;
            steps.pop_front();
            return result;
        }

        /** @brief Reject use of a zero-IV CMAC API for a retained-IV ISO session. */
        Result<Bytes> cmac(Cipher, ByteView, ByteView) override {
            return Error{ErrorCode::unsupported, "fixture forbids unchained CMAC"};
        }

        /** @brief ECDSA is unrelated to the ISO AES fixture. */
        Result<bool> verify_ecdsa(std::string_view, ByteView, ByteView, ByteView) override {
            return Error{ErrorCode::unsupported, "fixture has no ECDSA"};
        }
    };

    /** @brief Return the fixed three-APDU mutual ISO AES transcript for application key two. */
    std::deque<ReplayStep> authentication_steps() {
        return {{hex("0084000010"), hex("303132333435363738393a3b3c3d3e3f9000")},
                {hex("008209822007feef74e1d5036e900eee118e94929311f263c2ac89b42b2798698959a4ec86"),
                 hex("9000")},
                {hex("0088098210202122232425262728292a2b2c2d2e2f20"),
                 hex("67cabc580bbbcc1bd56aa3a168a914496e0c841e553e3bc7bcb476b580967a829000")}};
    }

    /** @brief Install independent encryption/decryption answers for the mutual proof. */
    void add_authentication_crypto(VectorCrypto& crypto, bool mismatch = false) {
        auto card_proof = hex("404142434445464748494a4b4c4d4e4f202122232425262728292a2b2c2d2e2f");
        if (mismatch) {
            card_proof.back() ^= 1;
        }
        crypto.steps.push_back(
            {hex("000102030405060708090a0b0c0d0e0f"), Bytes(16),
             hex("101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f"), true,
             hex("07feef74e1d5036e900eee118e94929311f263c2ac89b42b2798698959a4ec86")});
        crypto.steps.push_back(
            {hex("000102030405060708090a0b0c0d0e0f"), hex("11f263c2ac89b42b2798698959a4ec86"),
             hex("67cabc580bbbcc1bd56aa3a168a914496e0c841e553e3bc7bcb476b580967a82"), false,
             card_proof});
    }

    /** @brief Add independently calculated retained-CMAC AES blocks for one read response. */
    void add_read_crypto(VectorCrypto& crypto, std::string_view iv, std::string_view padded_block,
                         std::string_view full_mac) {
        const auto session_key = hex("10111213404142431c1d1e1f4c4d4e4f");
        crypto.steps.push_back(
            {session_key, Bytes(16), Bytes(16), true, hex("a36f329630891fb22e7b28b42dacdeb4")});
        crypto.steps.push_back({session_key, hex(iv), hex(padded_block), true, hex(full_mac)});
    }

    /** @brief Verify mutual proof, exact session-key slices, sequential CMAC IVs, and plain ISO
     * writes. */
    void check_authenticated_session() {
        auto transcript = authentication_steps();
        transcript.push_back({hex("00b0000004"), hex("01020304cc786ac568dff0669000")});
        transcript.push_back({hex("00b2020404"), hex("050607084707c96a851f99039000")});
        transcript.push_back({hex("00e2000002aabb"), hex("9000")});
        transcript.push_back({hex("00b0000004"), hex("090a0b0ce9972568c7ccb0e49000")});
        IsoFixture transport(std::move(transcript));
        VectorCrypto crypto;
        add_authentication_crypto(crypto);
        add_read_crypto(crypto, "00000000000000000000000000000000",
                        "8cbec95cc2a47ec8b9eca2d0b6b37bde", "cc786ac568dff066ea8aa5a08606d425");
        add_read_crypto(crypto, "cc786ac568dff066ea8aa5a08606d425",
                        "88bacd50c2a47ec8b9eca2d0b6b37bde", "4707c96a851f990347bfcae5b506323a");
        add_read_crypto(crypto, "4707c96a851f990347bfcae5b506323a",
                        "84b6c154c2a47ec8b9eca2d0b6b37bde", "e9972568c7ccb0e4657ac96a152299e1");
        auto session =
            aes::authenticate(transport.channel(), crypto, KeyReference::application(2).value(),
                              hex("000102030405060708090a0b0c0d0e0f"));
        expect(session && session.value()->valid() &&
                   session.value()->key_reference().value() == 0x82,
               "ISO mutual proof establishes a private session for the requested key");
        auto first = session.value()->execute(transport.channel(), crypto,
                                              Command::read_binary(address(), 4).value());
        expect(first && first.value().data == hex("01020304"), "verified read strips its MAC");
        auto second =
            session.value()->execute(transport.channel(), crypto,
                                     Command::read_records(2, 0, RecordSelection::one, 4).value());
        expect(second && second.value().data == hex("05060708"),
               "record read retains the previous full response CMAC");
        auto write = session.value()->execute(transport.channel(), crypto,
                                              Command::append_record(0, hex("aabb")).value());
        expect(write && write.value().data.empty() && session.value()->valid(),
               "successful ISO append preserves session without inventing an APDU MAC");
        auto third = session.value()->execute(transport.channel(), crypto,
                                              Command::read_binary(address(), 4).value());
        expect(third && third.value().data == hex("090a0b0c") && transport.remaining() == 0 &&
                   crypto.steps.empty(),
               "plain ISO write does not advance the retained read CMAC IV");
        auto reset = transport.reset();
        expect(static_cast<bool>(reset), "fixture reset succeeds");
        auto stale = session.value()->execute(transport.channel(), crypto,
                                              Command::read_binary(address(), 4).value());
        expect(!stale && stale.error().code == ErrorCode::card_removed && !session.value()->valid(),
               "transport reset invalidates ISO session before transmission");
    }

    /** @brief Fail closed on mismatched card proof and on forged authenticated read data. */
    void check_authentication_failures() {
        VectorCrypto mismatch_crypto;
        add_authentication_crypto(mismatch_crypto, true);
        IsoFixture mismatch_transport(authentication_steps());
        auto mismatch = aes::authenticate(mismatch_transport.channel(), mismatch_crypto,
                                          KeyReference::application(2).value(),
                                          hex("000102030405060708090a0b0c0d0e0f"));
        expect(!mismatch && mismatch.error().code == ErrorCode::authentication &&
                   mismatch.error().outcome == Outcome::unknown,
               "unproved card identity never produces a session");
        auto transcript = authentication_steps();
        transcript.push_back({hex("00b0000004"), hex("01020304cc786ac568dff0679000")});
        IsoFixture tampered_transport(std::move(transcript));
        VectorCrypto tampered_crypto;
        add_authentication_crypto(tampered_crypto);
        add_read_crypto(tampered_crypto, "00000000000000000000000000000000",
                        "8cbec95cc2a47ec8b9eca2d0b6b37bde", "cc786ac568dff066ea8aa5a08606d425");
        auto session = aes::authenticate(tampered_transport.channel(), tampered_crypto,
                                         KeyReference::application(2).value(),
                                         hex("000102030405060708090a0b0c0d0e0f"));
        expect(static_cast<bool>(session), "tamper fixture initially authenticates");
        auto bad = session.value()->execute(tampered_transport.channel(), tampered_crypto,
                                            Command::read_binary(address(), 4).value());
        expect(!bad && bad.error().code == ErrorCode::integrity && !session.value()->valid(),
               "forged MAC releases no data and erases session state");
        auto again = session.value()->execute(tampered_transport.channel(), tampered_crypto,
                                              Command::read_binary(address(), 4).value());
        expect(!again && again.error().code == ErrorCode::session_invalid,
               "invalidated session cannot be reused");
        VectorCrypto short_random;
        short_random.random_bytes.resize(31);
        IsoFixture idle({});
        auto bad_rng =
            aes::authenticate(idle.channel(), short_random, KeyReference::picc_master(), Bytes(16));
        expect(!bad_rng && bad_rng.error().code == ErrorCode::crypto &&
                   bad_rng.error().outcome == Outcome::not_sent,
               "short provider randomness fails before card state changes");
    }

    /** @brief Contain provider exceptions and distinguish pre-I/O randomness from partial proof. */
    void check_provider_exceptions() {
        VectorCrypto rng;
        rng.throw_random = true;
        IsoFixture idle(authentication_steps());
        auto rng_error =
            aes::authenticate(idle.channel(), rng, KeyReference::application(2).value(),
                              hex("000102030405060708090a0b0c0d0e0f"));
        expect(!rng_error && rng_error.error().code == ErrorCode::internal &&
                   rng_error.error().outcome == Outcome::not_sent && idle.remaining() == 3,
               "throwing RNG is contained before the first authentication frame");

        VectorCrypto proof;
        proof.throw_cbc = true;
        IsoFixture begun(authentication_steps());
        auto proof_error =
            aes::authenticate(begun.channel(), proof, KeyReference::application(2).value(),
                              hex("000102030405060708090a0b0c0d0e0f"));
        expect(!proof_error && proof_error.error().code == ErrorCode::internal &&
                   proof_error.error().outcome == Outcome::unknown && begun.remaining() == 2,
               "throwing CBC after GET CHALLENGE reports partial authentication uncertainty");

        VectorCrypto response_crypto;
        add_authentication_crypto(response_crypto);
        auto transcript = authentication_steps();
        transcript.push_back({hex("00b0000004"), hex("01020304cc786ac568dff0669000")});
        IsoFixture transport(std::move(transcript));
        auto session = aes::authenticate(transport.channel(), response_crypto,
                                         KeyReference::application(2).value(),
                                         hex("000102030405060708090a0b0c0d0e0f"));
        expect(static_cast<bool>(session), "exception fixture establishes a valid session");
        response_crypto.throw_cbc = true;
        auto failed_read = session.value()->execute(transport.channel(), response_crypto,
                                                    Command::read_binary(address(), 4).value());
        expect(!failed_read && failed_read.error().outcome == Outcome::unknown &&
                   !session.value()->valid() && transport.remaining() == 0,
               "throwing response CMAC primitive releases no data and invalidates its IV/key");
        auto repeated = session.value()->execute(transport.channel(), response_crypto,
                                                 Command::read_binary(address(), 4).value());
        expect(!repeated && repeated.error().code == ErrorCode::session_invalid,
               "a provider exception cannot resurrect an ISO secure session");
    }

    /** @brief Inject a throwing foreign reader without the protective callback adapter. */
    class ThrowingTransport final : public CardTransport {
    public:

        std::size_t calls{};

        /** @brief Advertise valid APDU limits so the failure occurs inside the exchange callback.
         */
        TransportCapabilities capabilities() const override {
            return {};
        }

        /** @brief Preserve a stable generation for the exception regression. */
        std::uint64_t generation() const noexcept override {
            return 1;
        }

        /** @brief No cancellation work is required by the throwing reader fixture. */
        void cancel() noexcept override {}

        /** @brief Throw after the engine has handed the APDU to the reader. */
        Result<Bytes> exchange(ByteView, const ExchangeOptions&) override {
            ++calls;
            throw std::runtime_error("injected transport exception");
        }
    };

    /** @brief Attempt same-channel callback reentry and retain the nested result for inspection. */
    class ReentrantTransport final : public CardTransport {
    public:

        raw::Channel* channel{};
        bool exchange_busy{};
        bool reset_busy{};

        /** @brief Advertise ordinary ISO APDU limits for both reentry paths. */
        TransportCapabilities capabilities() const override {
            TransportCapabilities result;
            result.can_reset = true;
            return result;
        }

        /** @brief Preserve one generation because the fixture performs no physical reset. */
        std::uint64_t generation() const noexcept override {
            return 1;
        }

        /** @brief No cancellation work is required by this synchronous fixture. */
        void cancel() noexcept override {}

        /** @brief Verify nested exchange and reset calls fail with busy before recursive I/O. */
        Result<Bytes> exchange(ByteView, const ExchangeOptions&) override {
            const auto nested_exchange = channel->exchange(raw::Apdu{.ins = 0x84});
            exchange_busy = !nested_exchange && nested_exchange.error().code == ErrorCode::busy &&
                            nested_exchange.error().outcome == Outcome::not_sent;
            const auto nested_reset = channel->reset();
            reset_busy = !nested_reset && nested_reset.error().code == ErrorCode::busy &&
                         nested_reset.error().outcome == Outcome::not_sent;
            return Bytes{0x90, 0x00};
        }

        /** @brief Return success when reset is invoked outside an active callback. */
        Result<void> reset() override {
            return {};
        }
    };

    /** @brief Reject moved-from data commands and contain arbitrary reader exceptions. */
    void check_moved_commands_and_transport_exception() {
        auto update = Command::update_binary(address(), hex("010203"));
        expect(static_cast<bool>(update), "moved-command fixture starts valid");
        auto retained = std::move(update.value());
        expect(static_cast<bool>(raw::encode(retained.apdu())),
               "moved destination retains exact mutation data");
        IsoFixture idle({});
        auto moved_from = idle.exchange(update.value());
        expect(!moved_from && moved_from.error().code == ErrorCode::invalid_argument &&
                   moved_from.error().outcome == Outcome::not_sent && idle.remaining() == 0,
               "checked channel rejects a moved-from mutation before I/O");
        auto transport = std::make_shared<ThrowingTransport>();
        auto* throwing = transport.get();
        auto raw_channel = raw::Channel::create(std::move(transport));
        expect(static_cast<bool>(raw_channel), "throwing raw channel fixture");
        checked::Channel channel(*raw_channel.value());
        auto result = channel.exchange(Command::read_binary(address(), 4).value());
        expect(!result && result.error().code == ErrorCode::transport &&
                   result.error().outcome == Outcome::unknown && throwing->calls == 1,
               "reader exception remains one uncertain attempt without escaping or retrying");
    }

    /** @brief Prove same-thread transport callback reentry returns busy without deadlocking. */
    void check_callback_reentry() {
        auto transport = std::make_shared<ReentrantTransport>();
        auto* reentrant = transport.get();
        auto opened = raw::Channel::create(std::move(transport));
        expect(static_cast<bool>(opened), "reentrant raw channel fixture");
        reentrant->channel = opened.value().get();
        const auto response = opened.value()->exchange(raw::Apdu{.ins = 0x84});
        expect(response && response.value().status == 0x9000 && reentrant->exchange_busy &&
                   reentrant->reset_busy,
               "same-channel exchange and reset callback reentry return busy");
        expect(static_cast<bool>(opened.value()->reset()),
               "channel remains usable after rejected callback reentry");
    }
} // namespace

/** @brief Run independent ISO framing, transport, mutual AES, and response-integrity checks. */
int main() {
    check_encoding();
    check_validation();
    check_status_and_continuation();
    check_length_correction();
    check_exchange_bounds();
    check_authenticated_session();
    check_authentication_failures();
    check_provider_exceptions();
    check_moved_commands_and_transport_exception();
    check_callback_reentry();
    std::cout << "EV3 ISO7816 tests passed.\n";
    return EXIT_SUCCESS;
}
