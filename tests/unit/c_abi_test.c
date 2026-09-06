/** @file c_abi_test.c @brief C99 ABI lifetime, buffer ownership and replay safety tests. */
#include <desfire.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fixture {
    unsigned calls;
    unsigned retains;
    unsigned releases;
    unsigned resolutions;
    df_card card;
    int reenter;
} fixture;

/** @brief Enforce observable C ABI behavior, including builds with NDEBUG. */
static void expect(int condition, const char* text) {
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", text);
        exit(1);
    }
}

/** @brief Assert exact wire commands and return bounded card responses. */
static int32_t exchange(void* context, const uint8_t* tx, size_t tx_size, uint8_t* rx,
                        size_t capacity, size_t* received, uint32_t timeout, df_error* error) {
    fixture* state = (fixture*)context;
    (void)timeout;
    (void)error;
    ++state->calls;
    expect(capacity >= 5, "advertised receive capacity");
    if (state->reenter) {
        uint32_t memory = 0;
        df_error nested;
        expect(df_free_memory(state->card, 100, &memory, &nested) == DF_BUSY,
               "callback reentry cannot deadlock");
    }
    if (tx_size == 5 && tx[0] == 0x90 && tx[1] == 0x6e) {
        rx[0] = 0x56;
        rx[1] = 0x34;
        rx[2] = 0x12;
        rx[3] = 0x91;
        rx[4] = 0;
        *received = 5;
        return 0;
    }
    if (tx_size == 5 && tx[0] == 0x90 && tx[1] == 0x6f) {
        rx[0] = 0;
        rx[1] = 31;
        rx[2] = 0x91;
        rx[3] = 0;
        *received = 4;
        return 0;
    }
    if (tx_size == 13 && tx[0] == 0x90 && tx[1] == 0xCD) {
        const uint8_t expected[] = {0x90, 0xCD, 0, 0, 7, 1, 0, 0x34, 0x12, 0x20, 0, 0, 0};
        expect(memcmp(tx, expected, sizeof(expected)) == 0, "packed rights 0x1234 encode as 34 12");
        rx[0] = 0x91;
        rx[1] = 0;
        *received = 2;
        return 0;
    }
    if (tx_size == 5 && tx[0] == 0x00 && tx[1] == 0x84) {
        rx[0] = 0xAB;
        rx[1] = 0x62;
        rx[2] = 0x83;
        *received = 3;
        return 0;
    }
    if (tx_size == 1 && tx[0] == 0x6E) {
        rx[0] = 0;
        rx[1] = 0x56;
        rx[2] = 0x34;
        rx[3] = 0x12;
        *received = 4;
        return 0;
    }
    return DF_TRANSPORT;
}

/** @brief Retain one test callback context. */
static void retain(void* context) {
    ++((fixture*)context)->retains;
}

/** @brief Release one test callback context. */
static void release(void* context) {
    ++((fixture*)context)->releases;
}

/** @brief Count provider calls; these focused preflight tests must never invoke it. */
static int32_t resolve_key(void* context, const df_key_request_v1* request, uint8_t* key,
                           size_t capacity, size_t* written, df_error* error) {
    fixture* state = (fixture*)context;
    size_t index;
    (void)request;
    (void)error;
    ++state->resolutions;
    expect(capacity == 16, "provider receives exact AES-128 capacity");
    for (index = 0; index < 16; ++index) {
        key[index] = 0;
    }
    *written = 16;
    return DF_OK;
}

/** @brief Simulate a confirmed reader/card reset. */
static int32_t reset(void* context, df_error* error) {
    (void)context;
    (void)error;
    return 0;
}

/** @brief Exercise C compatibility and state evidence without a C++ header. */
int main(void) {
    fixture state = {0};
    df_transport transport = {0};
    df_error error;
    df_card card = 0;
    transport.struct_size = sizeof(transport);
    transport.abi_version = DF_ABI_VERSION;
    transport.framing = DF_ISO_WRAPPED;
    transport.max_transmit = 261;
    transport.max_receive = 512;
    transport.max_native_frame = 60;
    transport.context = &state;
    transport.exchange = exchange;
    transport.reset = reset;
    transport.retain = retain;
    transport.release = release;
    expect(df_abi_version() == 1, "ABI version");
    expect(strcmp(df_manifest_sha256(), DESFIRE_EXPECTED_MANIFEST_SHA256) == 0,
           "embedded API manifest digest");
    {
        static const uint8_t master_key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        static const uint8_t diversification[17] = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D,
                                                    0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58,
                                                    0x50, 0x20, 0x41, 0x62, 0x75};
        static const uint8_t expected[16] = {0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3,
                                             0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75};
        df_buffer* derived = NULL;
        expect(df_offline_derive_nxp_aes128(master_key, sizeof(master_key), diversification,
                                            sizeof(diversification), &derived, &error) == DF_OK,
               "C offline AN10922 derivation");
        expect(df_buffer_size(derived) == sizeof(expected) &&
                   memcmp(df_buffer_data(derived), expected, sizeof(expected)) == 0,
               "C offline AN10922 published vector");
        df_buffer_free(derived);
    }
    {
        static const uint8_t transaction_key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        static const uint8_t uid[7] = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80};
        static const uint8_t expected_keys[32] = {0x2D, 0xB2, 0x06, 0xD2, 0x0F, 0x49, 0x3A, 0xC4,
                                                  0x52, 0x4E, 0xAD, 0xE9, 0x77, 0xE9, 0x76, 0xB4,
                                                  0xA0, 0xDD, 0x3E, 0xA5, 0x25, 0x46, 0xEC, 0x46,
                                                  0x2F, 0xE0, 0xF4, 0x66, 0xFE, 0xB3, 0xA6, 0x2F};
        static const uint8_t tmi[33] = {0x3D, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
                                        0x20, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        static const uint8_t expected_mac[8] = {0x1E, 0x28, 0x5E, 0x48, 0x5B, 0xA6, 0x2D, 0xE1};
        static const uint8_t encrypted_reader[16] = {0x4C, 0xBA, 0x54, 0x02, 0xF5, 0x72,
                                                     0x3F, 0xA3, 0x0D, 0xFC, 0xDF, 0x94,
                                                     0x77, 0xE6, 0x23, 0xF5};
        static const uint8_t expected_reader[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        df_buffer* result = NULL;
        uint32_t verified = 0;
        expect(df_offline_derive_transaction_mac_keys_aes(transaction_key, sizeof(transaction_key),
                                                          1, uid, sizeof(uid), &result,
                                                          &error) == DF_OK,
               "C transaction session-key derivation");
        expect(df_buffer_size(result) == sizeof(expected_keys) &&
                   memcmp(df_buffer_data(result), expected_keys, sizeof(expected_keys)) == 0,
               "C transaction session keys match independent answers");
        df_buffer_free(result);
        result = NULL;
        expect(df_offline_calculate_transaction_mac_session_aes(expected_keys, 16, tmi, sizeof(tmi),
                                                                &result, &error) == DF_OK,
               "C transaction session MAC calculation");
        expect(df_buffer_size(result) == sizeof(expected_mac) &&
                   memcmp(df_buffer_data(result), expected_mac, sizeof(expected_mac)) == 0,
               "C transaction MAC matches independent answer");
        df_buffer_free(result);
        result = NULL;
        expect(df_offline_verify_transaction_mac_aes(
                   transaction_key, sizeof(transaction_key), 1, uid, sizeof(uid), tmi, sizeof(tmi),
                   expected_mac, sizeof(expected_mac), &verified, &error) == DF_OK &&
                   verified == 1,
               "C transaction MAC verification");
        expect(df_offline_decrypt_transaction_reader_id_aes(
                   expected_keys + 16, 16, encrypted_reader, sizeof(encrypted_reader), &result,
                   &error) == DF_OK,
               "C transaction ReaderID recovery");
        expect(df_buffer_size(result) == sizeof(expected_reader) &&
                   memcmp(df_buffer_data(result), expected_reader, sizeof(expected_reader)) == 0,
               "C transaction ReaderID matches independent answer");
        df_buffer_free(result);
    }
    {
        static const uint8_t dam_mac_key[16] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
        static const uint8_t encrypted_default_key[32] = {
            0x92, 0x32, 0xC8, 0x2A, 0x91, 0x3F, 0xA1, 0xCF, 0xCD, 0xC7, 0xED,
            0x5E, 0xC6, 0x3A, 0xB4, 0x5C, 0xE9, 0x91, 0xC0, 0x6A, 0x1F, 0x48,
            0x51, 0x56, 0xDB, 0x8C, 0x3C, 0xDC, 0xB6, 0x89, 0xBD, 0x27};
        static const uint8_t expected_create_mac[8] = {0x5D, 0x94, 0x16, 0x83,
                                                       0xB9, 0x01, 0x61, 0x2B};
        static const uint8_t expected_delete_mac[8] = {0xDC, 0xD2, 0xF3, 0x0E,
                                                       0x70, 0x2C, 0x93, 0x70};
        static const uint8_t old_name[7] = {0xA0, 0x00, 0x00, 0x03, 0x96, 0x56, 0x43};
        static const uint8_t new_name[7] = {0xA0, 0x00, 0x00, 0x03, 0x96, 0x56, 0x44};
        static const uint8_t expected_configuration_mac[8] = {0xD2, 0x8C, 0xA6, 0x9A,
                                                              0x54, 0x45, 0x4B, 0x38};
        df_delegated_application_configuration_v1 configuration = {0};
        df_buffer* result = NULL;
        configuration.struct_size = sizeof(configuration);
        configuration.abi_version = DF_ABI_VERSION;
        configuration.application_id = 0x563412;
        configuration.key_settings = 0xEF;
        configuration.number_of_keys = 1;
        configuration.quota_limit = 0x40;
        configuration.key_settings3 = -1;
        configuration.iso_id = -1;
        expect(df_offline_calculate_delegated_application_mac_aes(
                   dam_mac_key, sizeof(dam_mac_key), &configuration, encrypted_default_key,
                   sizeof(encrypted_default_key), &result, &error) == DF_OK,
               "C delegated creation MAC calculation");
        expect(df_buffer_size(result) == sizeof(expected_create_mac) &&
                   memcmp(df_buffer_data(result), expected_create_mac,
                          sizeof(expected_create_mac)) == 0,
               "C delegated creation MAC matches AN12696");
        df_buffer_free(result);
        result = NULL;
        expect(df_offline_calculate_delegated_application_delete_mac_aes(
                   dam_mac_key, sizeof(dam_mac_key), 0x563412, &result, &error) == DF_OK,
               "C delegated delete MAC calculation");
        expect(df_buffer_size(result) == sizeof(expected_delete_mac) &&
                   memcmp(df_buffer_data(result), expected_delete_mac,
                          sizeof(expected_delete_mac)) == 0,
               "C delegated delete MAC matches independent answer");
        df_buffer_free(result);
        result = NULL;
        expect(df_offline_calculate_delegated_configuration_mac_aes(
                   dam_mac_key, sizeof(dam_mac_key), old_name, sizeof(old_name), new_name,
                   sizeof(new_name), &result, &error) == DF_OK,
               "C delegated configuration MAC calculation");
        expect(df_buffer_size(result) == sizeof(expected_configuration_mac) &&
                   memcmp(df_buffer_data(result), expected_configuration_mac,
                          sizeof(expected_configuration_mac)) == 0,
               "C delegated configuration MAC matches independent answer");
        df_buffer_free(result);
    }
    {
        static const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        static const uint8_t license[5] = {0x02, 0x04, 0xA1, 0x08, 0xB2};
        static const uint8_t secrets[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
        static const uint8_t expected[8] = {0x76, 0x6E, 0xDC, 0x89, 0x21, 0xF0, 0x3E, 0x2E};
        df_buffer* result = NULL;
        expect(df_offline_calculate_mfc_license_mac_aes(key, sizeof(key), license, sizeof(license),
                                                        secrets, sizeof(secrets), &result,
                                                        &error) == DF_OK,
               "C MIFARE Classic license MAC calculation");
        expect(df_buffer_size(result) == sizeof(expected) &&
                   memcmp(df_buffer_data(result), expected, sizeof(expected)) == 0,
               "C MIFARE Classic license MAC matches independent answer");
        df_buffer_free(result);
    }
    {
        fixture provider_state = {0};
        df_key_provider_v1 provider = {0};
        df_key_request_v1 request = {0};
        static const uint8_t reference[1] = {0x42};
        static const uint8_t uid[7] = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80};
        df_buffer* result = NULL;
        provider.struct_size = sizeof(provider);
        provider.abi_version = DF_ABI_VERSION;
        provider.context = &provider_state;
        provider.resolve = resolve_key;
        provider.retain = retain;
        provider.release = release;
        request.struct_size = sizeof(request);
        request.abi_version = DF_ABI_VERSION;
        request.purpose = DF_KEY_PURPOSE_TRANSACTION_MAC;
        request.authentication_profile = DF_OPTION_ABSENT;
        request.scope = DF_KEY_SCOPE_NATIVE;
        request.key_number = 0;
        request.application_id = DF_OPTION_ABSENT;
        request.key_set = DF_OPTION_ABSENT;
        request.reference = reference;
        request.reference_size = sizeof(reference);
        result = (df_buffer*)(uintptr_t)1;
        expect(df_offline_derive_transaction_mac_keys_aes_provider(&provider, &request, 1, uid,
                                                                   sizeof(uid), &result,
                                                                   &error) == DF_INVALID_ARGUMENT,
               "C offline provider rejects a nonempty output slot before resolution");
        expect(provider_state.resolutions == 0,
               "C offline invalid output has no provider callback side effect");
        result = NULL;
        expect(df_offline_derive_transaction_mac_keys_aes_provider(
                   &provider, &request, 1, uid, sizeof(uid), &result, &error) == DF_OK,
               "C offline provider resolves one scoped transaction key");
        expect(provider_state.resolutions == 1 && provider_state.retains == 1 &&
                   provider_state.releases == 1 && df_buffer_size(result) == 32,
               "C offline provider is retained, invoked and released exactly once");
        df_buffer_free(result);
        result = NULL;
        request.purpose = DF_KEY_PURPOSE_AUTHENTICATION;
        expect(df_offline_derive_transaction_mac_keys_aes_provider(&provider, &request, 1, uid,
                                                                   sizeof(uid), &result,
                                                                   &error) == DF_INVALID_ARGUMENT,
               "C offline provider purpose mismatch fails before resolution");
        expect(provider_state.resolutions == 1 && result == NULL,
               "C offline provider mismatch has no callback or output side effect");
    }
    expect(df_open(&transport, &card, &error) == 0 && card != 0, "open callback card");
    expect(state.retains == 1 && state.releases == 0, "managed transport retained once");
    state.card = card;
    state.reenter = 1;
    uint32_t memory = 0;
    expect(df_free_memory(card, 500, &memory, &error) == 0 && memory == 0x123456,
           "typed free memory");
    expect(df_file_ids(card, 500, NULL, &error) == DF_INVALID_ARGUMENT && state.calls == 1,
           "null output fails before I/O");
    df_buffer* output = NULL;
    expect(df_file_ids(card, 500, &output, &error) == 0, "owned file result");
    expect(df_buffer_size(output) == 2 && df_buffer_data(output)[1] == 31, "owned result contents");
    expect(df_file_ids(card, 500, &output, &error) == DF_INVALID_ARGUMENT && state.calls == 2,
           "nonempty result slot never reexecutes command");
    df_buffer_free(output);
    expect(df_notify_state_change(card, &error) == 0, "report card removal");
    expect(df_free_memory(card, 500, &memory, &error) == DF_CARD_REMOVED && state.calls == 2,
           "removal blocks I/O");
    expect(df_reset(card, &error) == 0, "reset recovery");
    expect(df_free_memory(card, 500, &memory, &error) == 0 && state.calls == 3,
           "read after confirmed reset");
    expect(df_create_data_file(card, 1, 32, DF_PLAIN, 0x1234, -1, 0, 500, &error) == DF_OK,
           "C access-rights nibbles preserve independently expected wire permissions");

    {
        df_raw_channel raw = 0;
        df_buffer* raw_output = NULL;
        uint32_t raw_status = 0xFFFFFFFFu;
        unsigned calls_before;
        df_iso_apdu_v1 apdu = {0};
        df_native_request_v1 native_request = {0};
        df_key_provider_v1 provider = {0};
        df_key_request_v1 request = {0};
        df_authentication_info_v1 authentication = {0};
        static const uint8_t reference[] = {0x01};

        state.reenter = 0;
        expect(df_raw_open(&transport, &raw, &error) == DF_OK && raw != 0,
               "open independent raw channel");
        expect(state.retains == 2 && state.releases == 0, "raw transport retained once");

        expect(df_raw_native_frame(raw, DF_ISO_WRAPPED, 0x6E, NULL, 0, 500, &raw_status,
                                   &raw_output, &error) == DF_OK,
               "raw physical native frame");
        expect(raw_status == 0 && df_buffer_size(raw_output) == 3 &&
                   df_buffer_data(raw_output)[0] == 0x56,
               "raw native status and data preserved");
        df_buffer_free(raw_output);
        raw_output = NULL;

        native_request.struct_size = sizeof(native_request);
        native_request.abi_version = DF_ABI_VERSION;
        native_request.framing = DF_ISO_WRAPPED;
        native_request.command = 0x6E;
        native_request.maximum_response = 3;
        native_request.first_frame_data_size = DF_RAW_NO_FIRST_FRAME_BOUNDARY;
        expect(df_raw_native_exchange(raw, &native_request, 500, &raw_status, &raw_output,
                                      &error) == DF_OK,
               "logical ISO-wrapped native exchange");
        expect(raw_status == 0 && df_buffer_size(raw_output) == 3,
               "logical ISO-wrapped response preserved");
        df_buffer_free(raw_output);
        raw_output = NULL;

        apdu.struct_size = sizeof(apdu);
        apdu.abi_version = DF_ABI_VERSION;
        apdu.ins = 0x84;
        apdu.has_le = 1;
        apdu.le = 8;
        apdu.length_encoding = DF_ISO_LENGTH_AUTOMATIC;
        apdu.maximum_response = 8;
        apdu.maximum_frames = 2;
        expect(df_raw_iso_exchange(raw, &apdu, 500, &raw_status, &raw_output, &error) == DF_OK,
               "true ISO raw exchange");
        expect(raw_status == 0x6283 && df_buffer_size(raw_output) == 1 &&
                   df_buffer_data(raw_output)[0] == 0xAB,
               "exact non-success ISO status preserved as raw result");
        df_buffer_free(raw_output);
        raw_output = NULL;

        apdu = (df_iso_apdu_v1){0};
        apdu.struct_size = sizeof(apdu);
        apdu.abi_version = DF_ABI_VERSION;
        apdu.ins = 0xB0;
        apdu.has_le = 1;
        apdu.le = 1;
        apdu.length_encoding = DF_ISO_LENGTH_AUTOMATIC;
        apdu.maximum_response = 1;
        apdu.maximum_frames = 2;
        calls_before = state.calls;
        expect(df_raw_iso_secure_exchange(raw, &apdu, 500, &raw_status, &raw_output, &error) ==
                   DF_SESSION_INVALID,
               "secure ISO exchange requires an active ISO AES session");
        expect(state.calls == calls_before && raw_output == NULL,
               "missing secure ISO session fails before card I/O");

        provider.struct_size = sizeof(provider);
        provider.abi_version = DF_ABI_VERSION;
        provider.context = &state;
        provider.resolve = resolve_key;
        provider.retain = retain;
        provider.release = release;
        request.struct_size = sizeof(request);
        request.abi_version = DF_ABI_VERSION;
        request.purpose = DF_KEY_PURPOSE_AUTHENTICATION;
        request.authentication_profile = DF_AUTH_PROFILE_EV2_NON_FIRST;
        request.scope = DF_KEY_SCOPE_NATIVE;
        request.key_number = 0;
        request.application_id = DF_OPTION_ABSENT;
        request.key_set = DF_OPTION_ABSENT;
        request.reference = reference;
        request.reference_size = sizeof(reference);
        authentication.struct_size = sizeof(authentication);
        authentication.abi_version = DF_ABI_VERSION;
        request.authentication_profile = DF_AUTH_PROFILE_EV2_FIRST;
        expect(df_raw_authenticate_standard_aes_provider(raw, 0, &provider, &request, 500,
                                                         &error) == DF_INVALID_ARGUMENT,
               "Standard AES rejects a mismatched provider profile");
        request.authentication_profile = DF_AUTH_PROFILE_STANDARD_AES;
        expect(df_raw_authenticate_ev2_first_aes_provider(raw, 0, &provider, &request, NULL, 0, 500,
                                                          &authentication,
                                                          &error) == DF_INVALID_ARGUMENT,
               "EV2 First rejects a mismatched provider profile");
        expect(df_raw_authenticate_iso_aes_provider(raw, 0, 0, &provider, &request, 500, &error) ==
                   DF_INVALID_ARGUMENT,
               "ISO AES rejects a mismatched provider profile");
        expect(state.calls == calls_before && state.resolutions == 0 && state.retains == 2,
               "mismatched raw providers perform no retain, resolution, or card I/O");
        request.authentication_profile = DF_AUTH_PROFILE_EV2_NON_FIRST;
        expect(df_raw_authenticate_ev2_non_first_aes_provider(
                   raw, 0, &provider, &request, 500, &authentication, &error) == DF_SESSION_INVALID,
               "EV2 NonFirst provider requires an active EV2 First session");
        expect(state.calls == calls_before && state.resolutions == 0,
               "missing-session provider path performs no resolution or card I/O");
        expect(state.retains == 3 && state.releases == 1,
               "provider context retain and release are paired");

        expect(df_raw_close(raw, &error) == DF_OK, "close raw channel");
        expect(state.releases == 2, "raw transport released after close");
    }
    {
        df_raw_channel raw = 0;
        df_buffer* raw_output = NULL;
        uint32_t raw_status = 0xFFFFFFFFu;
        df_native_request_v1 native_request = {0};

        transport.framing = DF_NATIVE;
        expect(df_raw_open(&transport, &raw, &error) == DF_OK, "open direct-native raw channel");
        expect(df_raw_native_frame(raw, DF_NATIVE, 0x6E, NULL, 0, 500, &raw_status, &raw_output,
                                   &error) == DF_OK,
               "direct native physical frame");
        expect(raw_status == 0 && df_buffer_size(raw_output) == 3, "direct native physical result");
        df_buffer_free(raw_output);
        raw_output = NULL;

        native_request.struct_size = sizeof(native_request);
        native_request.abi_version = DF_ABI_VERSION;
        native_request.framing = DF_NATIVE;
        native_request.command = 0x6E;
        native_request.maximum_response = 3;
        native_request.first_frame_data_size = DF_RAW_NO_FIRST_FRAME_BOUNDARY;
        expect(df_raw_native_exchange(raw, &native_request, 500, &raw_status, &raw_output,
                                      &error) == DF_OK,
               "logical direct native exchange");
        expect(raw_status == 0 && df_buffer_size(raw_output) == 3, "logical direct native result");
        df_buffer_free(raw_output);
        expect(df_raw_close(raw, &error) == DF_OK, "close direct-native raw channel");
        expect(state.retains == 4 && state.releases == 3,
               "direct-native transport retain and release paired");
    }
    expect(df_close(card, &error) == 0, "close");
    expect(state.retains == 4 && state.releases == 4,
           "all retained transport and provider contexts released");
    expect(df_close(card, &error) == DF_STALE_HANDLE, "double close safe");
    expect(df_free_memory(card, 500, &memory, &error) == DF_STALE_HANDLE, "stale handles rejected");
    puts("C99 ABI checks passed");
    return 0;
}
