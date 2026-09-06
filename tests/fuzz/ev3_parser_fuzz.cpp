/** @file ev3_parser_fuzz.cpp
 * @brief Exercise all untrusted binary parsers under libFuzzer and sanitizers.
 */
#include <cstddef>
#include <cstdint>
#include <desfire/ev3/iso7816/raw/codec.hpp>
#include <desfire/ev3/model/version.hpp>
#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/files.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>
#include <desfire/ev3/native/raw/codec.hpp>

/** @brief Parse arbitrary bytes without relying on validity or on roundtrip encoders.
 * @param data Borrowed fuzzer input.
 * @param size Input length bounded by the fuzz runner.
 * @return Zero; parser failures are expected, memory errors and exceptions are findings.
 */
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const desfire::ByteView input(data, size);
    (void)desfire::ev3::model::parse_version(input);
    (void)desfire::ev3::native::checked::parse_application_ids(input);
    (void)desfire::ev3::native::checked::parse_iso_file_ids(input);
    (void)desfire::ev3::native::checked::parse_df_name_frame(input);
    (void)desfire::ev3::native::checked::parse_key_settings(input);
    (void)desfire::ev3::native::checked::parse_file_settings(input);
    (void)desfire::ev3::native::checked::parse_value(input);
    (void)desfire::ev3::native::checked::parse_transaction_mac(input);
    (void)desfire::ev3::native::checked::parse_card_uid(input);
    (void)desfire::ev3::native::checked::parse_originality_signature(input);
    (void)desfire::ev3::native::raw::decode(input, desfire::ev3::native::Framing::direct);
    (void)desfire::ev3::native::raw::decode(input, desfire::ev3::native::Framing::iso_wrapped);
    (void)desfire::ev3::iso7816::raw::decode(input);
    return 0;
}
