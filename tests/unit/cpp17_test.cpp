/**
 * @file cpp17_test.cpp
 * @brief Verify the strict exception-free C++17 facade against the split C ABI.
 */
#include <desfire/cpp17.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <type_traits>

namespace {
    using namespace desfire::cpp17;

    /** @brief Deterministic one-frame callback state owned by the test. */
    struct ExchangeState final {
        Bytes expected;
        Bytes response;
        std::size_t exchanges{};
    };

    /** @brief Fail without relying on assertions disabled by NDEBUG. */
    void expect(bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            std::exit(1);
        }
    }

    /** @brief Execute one exact deterministic physical frame for C ABI facade tests. */
    std::int32_t exchange(void* context, const std::uint8_t* transmit, std::size_t transmit_size,
                          std::uint8_t* receive, std::size_t capacity, std::size_t* received,
                          std::uint32_t, df_error* error) {
        auto* state = static_cast<ExchangeState*>(context);
        ++state->exchanges;
        if (transmit_size != state->expected.size() || capacity < state->response.size() ||
            !std::equal(state->expected.begin(), state->expected.end(), transmit)) {
            if (error != nullptr) {
                *error = {};
                error->code = DF_TRANSPORT;
                error->outcome = DF_NOT_SENT;
                std::strcpy(error->message, "unexpected C++17 fixture frame");
            }
            return DF_TRANSPORT;
        }
        std::copy(state->response.begin(), state->response.end(), receive);
        *received = state->response.size();
        return DF_OK;
    }

    /** @brief Create one externally owned direct-native transport descriptor. */
    df_transport_v1 transport(ExchangeState& state) {
        df_transport_v1 result{};
        result.struct_size = sizeof(result);
        result.abi_version = DF_ABI_VERSION;
        result.framing = DF_NATIVE;
        result.max_transmit = 256;
        result.max_receive = 256;
        result.max_native_frame = 256;
        result.context = &state;
        result.exchange = &exchange;
        return result;
    }

    /** @brief Custom derivation fixture recording exactly one synchronous call. */
    class Deriver final : public Aes128KeyDeriver {
    public:

        std::size_t calls{};
        bool fail{};

        /** @brief Return a fresh zero key while recording one borrowed master/context pair. */
        Result<Aes128Key> derive(const Aes128Key& master,
                                 const Aes128DerivationContext& context) noexcept override {
            ++calls;
            saw_live_master = master.valid();
            saw_purpose = context.purpose;
            if (fail) {
                return Result<Aes128Key>::failure(
                    {ErrorCode::crypto, Outcome::unknown, 0x91AE, "derivation detail"});
            }
            return Aes128Key::import(Bytes(16));
        }

        bool saw_live_master{};
        KeyPurpose saw_purpose{KeyPurpose::offline_operation};
    };

    /** @brief Custom provider fixture supporting deterministic success and failure. */
    class Provider final : public Aes128KeyProvider {
    public:

        std::size_t calls{};
        bool fail{};
        AuthenticationProfile profile{AuthenticationProfile::iso_aes};

        /** @brief Resolve one fresh zero key or one explicit pre-I/O failure. */
        Result<Aes128Key> resolve(const KeyRequest& request) noexcept override {
            ++calls;
            if (request.authentication_profile) {
                profile = *request.authentication_profile;
            }
            if (fail) {
                return Result<Aes128Key>::failure(
                    {ErrorCode::crypto, Outcome::unknown, 0x91AE, "provider detail"});
            }
            return Aes128Key::import(Bytes(16));
        }
    };

    /** @brief Construct a valid Standard AES provider request. */
    KeyRequest standard_request() {
        KeyRequest request;
        request.reference = {0x01};
        request.context.purpose = KeyPurpose::authentication;
        request.context.key_number = KeyNumber::make(0).value();
        request.authentication_profile = AuthenticationProfile::standard_aes;
        request.scope = KeyScope::native;
        return request;
    }

    /** @brief Verify strong types, result ownership, and exact no-exception card call behavior. */
    void basic_contracts() {
        static_assert(__cplusplus == 201703L, "facade test must compile in exact C++17 mode");
        static_assert(!std::is_copy_constructible<raw::Buffer>::value,
                      "native buffers have one owner");
        static_assert(!std::is_copy_constructible<raw::Card>::value,
                      "native card handles have one owner");
        static_assert(!std::is_copy_constructible<Card>::value, "friendly cards have one owner");
        static_assert(!std::is_copy_constructible<Aes128Key>::value, "AES keys have one owner");
        static_assert(std::is_nothrow_move_constructible<Aes128Key>::value,
                      "AES key moves cannot fail");
        static_assert(desfire::bindings::generated::operations.size() == 120,
                      "generated C++ inventory must cover every fallible C operation");

        expect(raw::abi_version() == desfire::bindings::generated::abi_version &&
                   raw::manifest_sha256() == desfire::bindings::generated::manifest_sha256 &&
                   static_cast<bool>(raw::validate_native_identity()),
               "C++17 facade verifies the exact loaded ABI and manifest before opening");

        expect(!ApplicationId::make(0x1000000), "strong AID rejects a fourth byte");
        expect(!FileNumber::make(32), "strong file number rejects value 32");
        expect(!Aes128Key::import(Bytes(15)), "AES-128 key rejects fifteen bytes");

        auto key = Aes128Key::import(Bytes(16, 0xA5));
        expect(static_cast<bool>(key), "AES-128 key imports sixteen bytes");
        auto moved = std::move(key).value();
        expect(moved.valid(), "AES-128 key retains ownership after move");

        ExchangeState state{{0x6E}, {0x00, 0x01, 0x00, 0x00}};
        auto opened = Card::open(transport(state));
        expect(static_cast<bool>(opened), "friendly Card opens without card I/O");
        auto card = std::move(opened).value();
        auto memory = card.free_memory(std::chrono::milliseconds{250});
        expect(memory && memory.value() == 1 && state.exchanges == 1,
               "friendly Card uses chrono and preserves the scalar result");
        auto invalid_timeout = card.free_memory(std::chrono::milliseconds{0});
        expect(!invalid_timeout && invalid_timeout.error().code == ErrorCode::invalid_argument &&
                   invalid_timeout.error().outcome == Outcome::not_sent && state.exchanges == 1,
               "invalid chrono duration fails before C or card I/O");
        expect(static_cast<bool>(card.close()), "explicit friendly close succeeds");
    }

    /** @brief Verify raw Card, Buffer, and Channel preserve exact C ABI status and ownership. */
    void raw_contracts() {
        ExchangeState buffer_state{{0x6A}, {0x00}};
        auto opened = raw::Card::open(transport(buffer_state));
        expect(static_cast<bool>(opened), "raw Card opens");
        auto card = std::move(opened).value();
        auto applications = card.application_ids(250);
        expect(applications && applications.value().size() == 0 && buffer_state.exchanges == 1,
               "raw Buffer owns one empty C ABI response without repeating I/O");
        const auto stale_handle = card.native_handle();
        auto moved = std::move(card);
        expect(card.native_handle() == 0 && moved.native_handle() == stale_handle,
               "raw Card move transfers only native handle ownership");
        expect(static_cast<bool>(moved.close()), "raw Card explicit close succeeds");
        std::uint32_t ignored{};
        df_error stale_error{};
        expect(df_free_memory(stale_handle, 250, &ignored, &stale_error) == DF_STALE_HANDLE,
               "closed raw handle is rejected by the C registry");

        ExchangeState frame_state{{0x6E}, {0x00, 0x01, 0x00, 0x00}};
        auto raw_opened = raw::Channel::open(transport(frame_state));
        expect(static_cast<bool>(raw_opened), "raw Channel opens");
        auto channel = std::move(raw_opened).value();
        auto response = channel.native_frame(DF_NATIVE, 0x6E, nullptr, 0, 250);
        expect(response && response.value().status == 0 && response.value().data.size() == 3 &&
                   response.value().data.data()[0] == 1 && frame_state.exchanges == 1,
               "raw Channel preserves status separately from its owned response buffer");
        expect(static_cast<bool>(channel.close()), "raw Channel explicit close succeeds");
    }

    /** @brief Verify Direct, Derived, and Provider key sources cross the facade exactly once. */
    void key_source_contracts() {
        auto imported = Aes128Key::import(Bytes(16));
        expect(static_cast<bool>(imported), "direct authentication key fixture imports");
        auto key = std::move(imported).value();
        const auto number = KeyNumber::make(0).value();

        ExchangeState direct_state{{0xAA, 0x00}, {0xAF}};
        auto direct_opened = Card::open(transport(direct_state));
        auto direct = std::move(direct_opened).value();
        auto direct_result = direct.authenticate_standard_aes(number, key);
        expect(!direct_result && direct_result.error().code == ErrorCode::malformed_response &&
                   direct_state.exchanges == 1,
               "direct key reaches exactly one initial authentication frame");

        ExchangeState derived_state{{0xAA, 0x00}, {0xAF}};
        auto derived_opened = Card::open(transport(derived_state));
        auto derived_card = std::move(derived_opened).value();
        Deriver deriver;
        Aes128DerivationContext context;
        context.purpose = KeyPurpose::authentication;
        context.key_number = number;
        auto derived_result = derived_card.authenticate_standard_aes(key, deriver, context);
        expect(!derived_result && derived_result.error().code == ErrorCode::malformed_response &&
                   deriver.calls == 1 && deriver.saw_live_master &&
                   deriver.saw_purpose == KeyPurpose::authentication &&
                   derived_state.exchanges == 1,
               "custom derivation runs once before one initial authentication frame");
        auto oversized_capabilities = derived_card.authenticate_ev2_first_aes_with_capabilities(
            key, deriver, context, Bytes(7));
        expect(!oversized_capabilities &&
                   oversized_capabilities.error().code == ErrorCode::invalid_argument &&
                   oversized_capabilities.error().outcome == Outcome::not_sent &&
                   deriver.calls == 1 && derived_state.exchanges == 1,
               "invalid EV2 capabilities fail before derivation and card I/O");

        ExchangeState provider_state{{0xAA, 0x00}, {0xAF}};
        auto provider_opened = Card::open(transport(provider_state));
        auto provider_card = std::move(provider_opened).value();
        Provider provider;
        auto request = standard_request();
        auto provider_result = provider_card.authenticate_standard_aes(provider, request);
        expect(!provider_result && provider_result.error().code == ErrorCode::malformed_response &&
                   provider.calls == 1 && provider.profile == AuthenticationProfile::standard_aes &&
                   provider_state.exchanges == 1,
               "custom provider resolves once before one initial authentication frame");

        ExchangeState failed_state{{0xAA, 0x00}, {0xAF}};
        auto failed_opened = Card::open(transport(failed_state));
        auto failed_card = std::move(failed_opened).value();
        Provider failed_provider;
        failed_provider.fail = true;
        auto provider_failure =
            failed_card.authenticate_standard_aes(failed_provider, standard_request());
        expect(!provider_failure && provider_failure.error().code == ErrorCode::crypto &&
                   provider_failure.error().outcome == Outcome::not_sent &&
                   provider_failure.error().device_status == 0 && failed_provider.calls == 1 &&
                   failed_state.exchanges == 0,
               "provider failure is normalized before card I/O");
    }

    /** @brief Verify expanded offline wrappers against independent transaction AES answers. */
    void offline_contracts() {
        const Bytes backend_bytes{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const Bytes uid{0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80};
        const Bytes input{0x3D, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x20, 0x30, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const Bytes expected_mac{0x1E, 0x28, 0x5E, 0x48, 0x5B, 0xA6, 0x2D, 0xE1};
        auto imported = Aes128Key::import(backend_bytes);
        expect(static_cast<bool>(imported), "offline backend key imports");
        auto backend = std::move(imported).value();
        auto keys = offline::derive_transaction_mac_keys_aes(backend, 1, uid);
        expect(keys &&
                   keys.value().mac_key == Bytes{0x2D, 0xB2, 0x06, 0xD2, 0x0F, 0x49, 0x3A, 0xC4,
                                                 0x52, 0x4E, 0xAD, 0xE9, 0x77, 0xE9, 0x76, 0xB4} &&
                   keys.value().encryption_key == Bytes{0xA0, 0xDD, 0x3E, 0xA5, 0x25, 0x46, 0xEC,
                                                        0x46, 0x2F, 0xE0, 0xF4, 0x66, 0xFE, 0xB3,
                                                        0xA6, 0x2F},
               "C++17 transaction key derivation matches independent answers");
        auto session_import = Aes128Key::import(keys.value().mac_key);
        expect(static_cast<bool>(session_import), "derived transaction MAC key imports");
        auto session_key = std::move(session_import).value();
        auto calculated = offline::calculate_transaction_mac_session_aes(session_key, input);
        expect(calculated && calculated.value() == expected_mac,
               "C++17 transaction MAC matches independent answer");
        auto verified = offline::verify_transaction_mac_aes(backend, 1, uid, input, expected_mac);
        expect(verified && verified.value(), "C++17 transaction MAC verifies");

        Provider provider;
        KeyRequest request;
        request.reference = {0x42};
        request.context.purpose = KeyPurpose::transaction_mac;
        request.context.key_number = KeyNumber::make(0).value();
        auto provider_keys = offline::derive_transaction_mac_keys_aes(provider, request, 1, uid);
        expect(provider_keys && provider.calls == 1,
               "C++17 offline provider resolves exactly one transaction key");

        Deriver failed_deriver;
        failed_deriver.fail = true;
        Aes128DerivationContext derivation_context;
        derivation_context.purpose = KeyPurpose::offline_operation;
        derivation_context.key_number = KeyNumber::make(0).value();
        auto derivation_failure = offline::derive_aes128_key(
            backend, failed_deriver, derivation_context, KeyPurpose::offline_operation);
        expect(!derivation_failure && derivation_failure.error().code == ErrorCode::crypto &&
                   derivation_failure.error().outcome == Outcome::not_sent &&
                   derivation_failure.error().device_status == 0 && failed_deriver.calls == 1,
               "offline custom derivation failures are truthful pre-I/O evidence");
    }
} // namespace

/** @brief Run strict C++17 ownership, raw, key-source, and no-exception regressions. */
int main() {
    basic_contracts();
    raw_contracts();
    key_source_contracts();
    offline_contracts();
    std::cout << "C++17 facade passed\n";
}
