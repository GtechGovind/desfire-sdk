/**
 * @file ev3_native_checked_test.cpp
 * @brief Golden EV3 command fields, strict response layouts, and boundary rejection.
 */
#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/files.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>
#include <type_traits>

namespace {

    using namespace desfire;
    using namespace desfire::ev3;
    using namespace desfire::ev3::model;
    using namespace desfire::ev3::native::checked;

    static_assert(!std::is_default_constructible_v<Command>);
    static_assert(!std::is_copy_constructible_v<Command>);
    static_assert(std::is_move_constructible_v<Command>);
    static_assert(std::is_same_v<decltype(std::declval<const Command&>().data()), ByteView>);

    /** @brief Stop the process when an independent expected invariant is violated. */
    void expect(bool condition, std::string_view description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << '\n';
            std::exit(EXIT_FAILURE);
        }
    }

    /** @brief Decode non-secret hexadecimal fixtures and reject test authoring mistakes. */
    Bytes hex(std::string_view source) {
        auto result = from_hex(source);
        expect(static_cast<bool>(result), "hex fixture is valid");
        return std::move(result.value());
    }

    /** @brief Build a checked numeric fixture and fail immediately for an invalid test value. */
    template <class NumberType> NumberType number(std::uint32_t value) {
        auto result = NumberType::make(value);
        expect(static_cast<bool>(result), "number fixture is valid");
        return result.value();
    }

    /** @brief Compare the command opcode and split wire fields against literal expectations. */
    void expect_command(const Result<Command>& result, Byte opcode, std::string_view header,
                        std::string_view data = {}) {
        expect(static_cast<bool>(result), "command encoding succeeds");
        expect(result.value().opcode() == opcode, "native opcode matches expected command");
        expect(result.value().header() == hex(header), "clear command header matches wire fixture");
        const auto expected_data = hex(data);
        expect(std::ranges::equal(result.value().data(), expected_data),
               "protected data matches wire fixture");
    }

    /** @brief Verify AES application optional fields and reject impossible combinations. */
    void check_application_commands() {
        ApplicationConfiguration application{number<ApplicationId>(0x123456)};
        expect_command(create_application(application), 0xCA, "5634120f81");
        application.number_of_keys = 5;
        application.iso_file_identifiers = true;
        application.key_settings3 = 0x14;
        application.key_sets = KeySetConfiguration{0x12, 3, 16, 0x0F};
        application.iso_id = 0xE110;
        application.df_name = hex("a0000003965643");
        expect_command(create_application(application), 0xCA,
                       "5634120fb5151203100f10e1a0000003965643");
        application.iso_id.reset();
        expect(!create_application(application), "DF name requires an ISO identifier");
        application.df_name.clear();
        application.number_of_keys = 15;
        expect(!create_application(application), "at most fourteen application keys");
        application.number_of_keys = 1;
        application.key_settings3 = 0x80;
        expect(!create_application(application), "reserved key-settings bits rejected");
        expect_command(delete_application(number<ApplicationId>(0x123456)), 0xDA, "563412");
        expect(!delete_application(number<ApplicationId>(0)), "PICC cannot be deleted");
        expect_command(get_version(), 0x60, "");
        expect_command(free_memory(), 0x6E, "");
        expect_command(get_file_ids(), 0x6F, "");
        expect_command(get_application_ids(), 0x6A, "");
        expect_command(get_df_names(), 0x6D, "");
        expect_command(get_iso_file_ids(), 0x61, "");
    }

    /** @brief Verify delegated application authorization fields and strict response decoding. */
    void check_delegated_application_commands() {
        const auto aid = number<ApplicationId>(0x123456);
        DelegatedApplicationConfiguration delegated{ApplicationConfiguration{aid}, 0x0102, 0x03,
                                                    0x0405};
        const auto encrypted_key =
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const auto dam_mac = hex("a0a1a2a3a4a5a6a7");
        auto create = create_delegated_application(delegated, encrypted_key, dam_mac);
        expect_command(create, 0xC9, "56341202010305040f81",
                       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                       "a0a1a2a3a4a5a6a7");
        expect(create.value().requires_authentication() && create.value().requires_ev2_session() &&
                   create.value().requires_picc_selection() &&
                   create.value().requires_single_continuation_frame() &&
                   create.value().current_authenticated_key() == 0x10 &&
                   create.value().request_mode() == CommunicationMode::mac &&
                   create.value().first_frame_payload_size() == create.value().header().size(),
               "delegated creation requires PICC DAM EV2 authentication and an exact AF boundary");

        auto extended = delegated;
        extended.application.number_of_keys = 5;
        extended.application.iso_file_identifiers = true;
        extended.application.key_settings3 = 0x14;
        extended.application.key_sets = KeySetConfiguration{0x12, 3, 16, 0x0F};
        extended.application.iso_id = 0xE110;
        extended.application.df_name = hex("a0000003965643");
        expect_command(create_delegated_application(extended, encrypted_key, dam_mac), 0xC9,
                       "56341202010305040fb5151203100f10e1a0000003965643",
                       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                       "a0a1a2a3a4a5a6a7");
        expect(!create_delegated_application(delegated, ByteView(encrypted_key).first(31), dam_mac),
               "truncated delegated encrypted key rejected");
        expect(!create_delegated_application(delegated, encrypted_key, ByteView(dam_mac).first(7)),
               "truncated delegated authorization MAC rejected");

        auto info_command = get_delegated_application_info(0x1234);
        expect_command(info_command, 0x69, "3412");
        expect(info_command.value().requires_picc_selection(),
               "delegated slot query requires tracked PICC selection");
        auto remove = delete_delegated_application(aid, dam_mac);
        expect_command(remove, 0xDA, "563412a0a1a2a3a4a5a6a7");
        expect(remove.value().requires_authentication() && !remove.value().requires_ev2_session() &&
                   remove.value().requires_picc_selection() &&
                   remove.value().restricts_authenticated_key() &&
                   remove.value().accepts_authenticated_key(0x10) &&
                   remove.value().accepts_authenticated_key(0x18) &&
                   !remove.value().accepts_authenticated_key(0x11),
               "delegated deletion accepts only either documented PICC DAM authentication key");
        expect(!delete_delegated_application(number<ApplicationId>(0), dam_mac),
               "delegated deletion rejects the PICC identifier");

        auto info = parse_delegated_application_info(hex("0734127856563412"));
        expect(info && info.value().slot_version == 7 && info.value().quota_limit == 0x1234 &&
                   info.value().free_blocks == 0x5678 &&
                   info.value().application.value() == 0x123456,
               "delegated information preserves exact little-endian fields");
        auto empty = parse_delegated_application_info(hex("0000000000000000"));
        expect(empty && empty.value().application.value() == 0,
               "an unoccupied delegated slot preserves its documented zero AID");
        expect(!parse_delegated_application_info(Bytes(7)),
               "truncated delegated information is rejected");
        expect(!parse_delegated_application_info(Bytes(9)),
               "delegated information rejects trailing data");
    }

    /** @brief Verify every file-creation type and their independent field order. */
    void check_file_creation() {
        const auto file = number<FileNumber>(5);
        const AccessRights access{1, 2, 3, 4};
        DataFileConfiguration data{file, number<ByteCount>(0x123456)};
        data.communication = CommunicationMode::full;
        data.access = access;
        data.iso_id = 0xE104;
        expect_command(create_data_file(data), 0xCD, "0504e1031234563412");
        data.backup = true;
        expect_command(create_data_file(data), 0xCB, "0504e1031234563412");
        data.backup = false;
        data.additional_access_rights = true;
        expect_command(create_data_file(data), 0xCD, "0504e1831234563412");

        ValueFileConfiguration value{file, -100, 1000, 7};
        value.access = access;
        value.limited_credit_enabled = true;
        value.free_get_value = true;
        expect_command(create_value_file(value), 0xCC, "050312349cffffffe80300000700000003");
        value.initial_value = -101;
        expect(!create_value_file(value), "initial value must be within signed limits");

        RecordFileConfiguration record{file, number<ByteCount>(32), number<ByteCount>(100)};
        record.access = access;
        expect_command(create_record_file(record), 0xC1, "05001234200000640000");
        record.cyclic = true;
        record.iso_id = 0xE105;
        expect_command(create_record_file(record), 0xC0, "0505e1001234200000640000");

        const auto key = hex("000102030405060708090a0b0c0d0e0f");
        auto transaction = create_transaction_mac_file(file, access, key, 0x42);
        expect_command(transaction, 0xCE, "0500123402", "000102030405060708090a0b0c0d0e0f42");
        expect(transaction.value().requires_authentication() &&
                   transaction.value().request_mode() == CommunicationMode::full &&
                   transaction.value().response_mode() == CommunicationMode::mac,
               "TMAC creation keeps key material inside full protection");
        expect(!create_transaction_mac_file(file, access, ByteView(key).first(15), 0),
               "TMAC key length checked before allocation");
    }

    /** @brief Verify read/write/value/record split headers and independent security directions. */
    void check_data_commands() {
        const auto file = number<FileNumber>(7);
        const auto offset = number<Offset>(0x123456);
        const auto length = number<ByteCount>(0x010203);
        const auto payload = hex("aabbcc");
        auto read = read_data(file, offset, length, CommunicationMode::full);
        expect_command(read, 0xBD, "07563412030201");
        expect(read.value().request_mode() == CommunicationMode::mac &&
                   read.value().response_mode() == CommunicationMode::full &&
                   read.value().minimum_response() == 0x010203 &&
                   read.value().maximum_response() == 0x010203,
               "full reads MAC the clear request and encrypt exactly bounded responses");
        expect_command(write_data(file, offset, payload, CommunicationMode::full), 0x3D,
                       "07563412030000", "aabbcc");
        expect_command(write_record(file, offset, payload, CommunicationMode::mac), 0x3B,
                       "07563412030000", "aabbcc");
        expect_command(
            update_record(file, number<Offset>(9), offset, payload, CommunicationMode::plain), 0xDB,
            "07090000563412030000", "aabbcc");
        expect_command(
            read_records(file, number<Offset>(9), number<ByteCount>(2), CommunicationMode::mac),
            0xBB, "07090000020000");
        expect_command(credit(file, 0x12345678, CommunicationMode::full), 0x0C, "07", "78563412");
        expect_command(debit(file, 0x12345678, CommunicationMode::mac), 0xDC, "07", "78563412");
        expect_command(limited_credit(file, 0x12345678, CommunicationMode::plain), 0x1C, "07",
                       "78563412");
        auto restore =
            restore_transfer(number<FileNumber>(2), number<FileNumber>(3), CommunicationMode::mac);
        expect_command(restore, 0xB1, "", "0203");
        expect(restore.value().requires_authentication() &&
                   restore.value().request_mode() == CommunicationMode::mac &&
                   restore.value().response_mode() == CommunicationMode::mac,
               "RestoreTransfer MAC protects target then source as command data");
        auto plain_restore = restore_transfer(number<FileNumber>(31), number<FileNumber>(0),
                                              CommunicationMode::plain);
        expect_command(plain_restore, 0xB1, "", "1f00");
        expect(!plain_restore.value().requires_authentication(),
               "RestoreTransfer Plain supports the complete native file-number range");
        expect(!restore_transfer(number<FileNumber>(2), number<FileNumber>(3),
                                 CommunicationMode::full),
               "RestoreTransfer rejects the undocumented Full communication variant");
        expect_command(get_value(file, CommunicationMode::full), 0x6C, "07");
        expect(!credit(file, 0x80000000U, CommunicationMode::plain),
               "unsigned values cannot silently become negative credits");
        expect(!write_data(file, offset, {}, CommunicationMode::plain),
               "empty data writes rejected");
        expect(!read_data(file, number<Offset>(0xFFFFFE), number<ByteCount>(2),
                          CommunicationMode::plain),
               "offset plus length cannot exceed maximum file size");
        expect(!read_data(file, offset, length, static_cast<CommunicationMode>(2)),
               "reserved communication mode rejected");
        expect(!read_records(file, offset, length, CommunicationMode::plain, 0),
               "zero response resource budget rejected");
        expect_command(clear_record_file(file), 0xEB, "07");
        expect_command(delete_file(file), 0xDF, "07");
        expect_command(get_file_settings(file), 0xF5, "07");
        auto counters = get_file_counters(file, CommunicationMode::full);
        expect_command(counters, 0xF6, "07");
        expect(counters.value().minimum_response() == 5 && counters.value().maximum_response() == 5,
               "file counters include three counter bytes and two reserved bytes");
    }

    /** @brief Verify AES key replacement payloads, CRC convention, and session-reset semantics. */
    void check_key_management() {
        const auto first = number<KeyNumber>(0);
        const auto other = number<KeyNumber>(1);
        const auto key = hex("000102030405060708090a0b0c0d0e0f");
        const Bytes old_key(16, 0xFF);
        auto current = change_aes_key(first, key, 0x42, first);
        expect(current && current.value().current_authenticated_key() == 0,
               "key change retains immutable authentication-selector assumptions");
        expect_command(current, 0xC4, "00", "000102030405060708090a0b0c0d0e0f42");
        expect(current.value().invalidates_session() &&
                   current.value().response_mode() == CommunicationMode::plain,
               "current-key replacement expects status only then clears the session");
        auto changed = change_aes_key(other, key, 0x42, first, old_key);
        expect_command(changed, 0xC4, "01", "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f042771d3131");
        expect(!changed.value().invalidates_session() &&
                   changed.value().response_mode() == CommunicationMode::mac,
               "another key replacement retains authenticated response requirements");
        expect_command(change_aes_key(first, key, 0x42, first, old_key, 2), 0xC6, "0200",
                       "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f042771d3131");
        auto key_set_change = change_aes_key(first, key, 0x42, first, old_key, 2);
        expect(!key_set_change.value().requires_ev2_session(),
               "ChangeKeyEV2 accepts either documented native AES session family");
        auto active_set_change = change_aes_key(first, key, 0x42, first, {}, 0);
        expect_command(active_set_change, 0xC6, "0000", "000102030405060708090a0b0c0d0e0f42");
        expect(active_set_change.value().invalidates_session(),
               "ChangeKeyEV2 active set treats the authenticated key as current");
        expect(!change_aes_key(first, key, 0x42, first, old_key, 0),
               "ChangeKeyEV2 active current key rejects a misleading old key");
        expect(!change_aes_key(first, key, 0x42, first, {}, 1),
               "ChangeKeyEV2 inactive set requires old key even for the same key number");
        expect_command(change_aes_key(first, key, 0x42, first, {}, {}, true), 0xC4, "80",
                       "000102030405060708090a0b0c0d0e0f42");
        expect(!change_aes_key(other, key, 0, first), "another key requires old key");
        expect(!change_aes_key(first, key, 0, first, old_key),
               "current key rejects a misleading old-key parameter");
        expect_command(get_key_version(other), 0x64, "01");
        expect_command(get_key_version(other, 3), 0x64, "4103");
        expect_command(get_key_set_versions(), 0x64, "4080");
        auto initialize = initialize_key_set(2);
        expect_command(initialize, 0x56, "", "0202");
        expect(initialize.value().requires_authentication() &&
                   !initialize.value().requires_ev2_session(),
               "InitializeKeySet accepts Standard AES and EV2 AES but never unauthenticated use");
        auto finalize = finalize_key_set(2, 0x44);
        expect_command(finalize, 0x57, "", "0244");
        expect(finalize.value().requires_authentication() &&
                   !finalize.value().requires_ev2_session(),
               "FinalizeKeySet accepts either authenticated AES session family");
        auto roll = roll_key_set(2);
        expect_command(roll, 0x55, "", "02");
        expect(roll.value().invalidates_session() &&
                   roll.value().response_mode() == CommunicationMode::mac &&
                   !roll.value().requires_ev2_session(),
               "key-set roll verifies either AES response MAC before session reset");
        expect(!initialize_key_set(16), "out-of-range key set rejected");
        expect_command(change_key_settings(0x0F), 0x54, "", "0f");
        expect_command(get_key_settings(), 0x45, "");
    }

    /** @brief Verify all response types reject truncation, duplicates, and trailing data. */
    void check_response_parsers() {
        auto applications = parse_application_ids(hex("010000563412"));
        expect(applications && applications.value().size() == 2 &&
                   applications.value()[1].value() == 0x123456,
               "application IDs preserve three-byte little-endian order");
        expect(!parse_application_ids(hex("010000010000")), "duplicate AIDs rejected");
        expect(!parse_application_ids(hex("000000")), "PICC AID rejected from application list");
        expect(!parse_application_ids(hex("0100")), "partial AID rejected");
        auto iso = parse_iso_file_ids(hex("04e105e1"));
        expect(iso && iso.value() == std::vector<std::uint16_t>{0xE104, 0xE105},
               "ISO identifiers are little-endian");
        expect(!parse_iso_file_ids(hex("04e104e1")), "duplicate ISO identifiers rejected");
        auto name = parse_df_name_frame(hex("56341210e1a0000003965643"));
        expect(name && name.value().application.value() == 0x123456 &&
                   name.value().iso_id == 0xE110 && name.value().name == hex("a0000003965643"),
               "DF-name frame retains its variable-length name");
        expect(!parse_df_name_frame(Bytes(22, 1)), "DF names cannot exceed one record");
        auto settings = parse_key_settings(hex("0f851203100f"));
        expect(settings && settings.value().key_set_details.has_value(),
               "extended key settings preserved");
        expect(!parse_key_settings(hex("0f8500")), "unexpected key-settings length rejected");

        const auto data_fixture = hex("00031234400000");
        auto data = parse_file_settings(data_fixture);
        expect(data && data.value().access == AccessRights{1, 2, 3, 4} &&
                   std::get<DataFileSettings>(data.value().details).size == 64,
               "data-file settings decode access nibbles and size");
        for (std::size_t length = 0; length < data_fixture.size(); ++length) {
            expect(!parse_file_settings(ByteView(data_fixture).first(length)),
                   "every truncation of a data-file response rejected");
        }
        auto extended = parse_file_settings(hex("008312344000000212345678"));
        expect(extended && extended.value().additional_access.size() == 2 &&
                   extended.value().additional_access[1] == AccessRights{5, 6, 7, 8},
               "additional access count determines exact trailing length");
        expect(!parse_file_settings(hex("00831234400000021234")),
               "truncated additional rights rejected");
        expect(!parse_file_settings(hex("0003123440000000")), "unexpected trailing bytes rejected");
        auto value = parse_file_settings(hex("020312349cffffffe80300000700000003"));
        expect(value && std::get<ValueFileSettings>(value.value().details).lower_limit == -100 &&
                   std::get<ValueFileSettings>(value.value().details).free_get_value,
               "signed value limits and flags decoded");
        auto record = parse_file_settings(hex("04001234200000640000020000"));
        expect(record && std::get<RecordFileSettings>(record.value().details).current_records == 2,
               "record count decoded independently of byte size");
        auto transaction = parse_file_settings(hex("05201234024478563412"));
        expect(transaction && transaction.value().transaction_counter_limit == 0x12345678 &&
                   std::get<TransactionMacFileSettings>(transaction.value().details).key_version ==
                       0x44,
               "TMAC file settings include optional four-byte counter limit");
        expect(!parse_file_settings(hex("06001234000000")), "unknown file type rejected");
        auto counters = parse_file_counters(hex("563412aabb"));
        expect(counters && counters.value().sdm_read_counter == 0x123456 &&
                   counters.value().reserved == std::array<Byte, 2>{0xAA, 0xBB},
               "file counters preserve reserved bytes instead of confusing them with MAC data");
        expect(!parse_file_counters(hex("563412")), "truncated file-counter response rejected");
        auto negative = parse_value(hex("00000080"));
        expect(negative && negative.value() == std::numeric_limits<std::int32_t>::min(),
               "value parser preserves signed minimum without implementation-defined conversion");
        expect(!parse_value(hex("0000000000")), "value trailing byte rejected");
        auto mac = parse_transaction_mac(hex("785634120001020304050607"));
        expect(mac && mac.value().counter == 0x12345678 && mac.value().mac[7] == 7,
               "transaction MAC counter and value kept distinct");
        expect(!parse_transaction_mac(Bytes(11)), "truncated transaction MAC rejected");
        expect(static_cast<bool>(parse_card_uid(hex("04010203040506"))), "seven-byte UID accepted");
        auto short_uid = parse_card_uid(hex("000401020304"));
        expect(short_uid && short_uid.value().uid == hex("01020304") && !short_uid.value().nuid,
               "four-byte UID format and length prefix removed");
        expect(static_cast<bool>(parse_card_uid(hex("000a00010203040506070809"))),
               "ten-byte UID prefix accepted");
        expect(!parse_card_uid(hex("010401020304")), "unknown UID format rejected");
        expect(!parse_card_uid(hex("000501020304")), "UID prefix length must match payload");
        auto uid_and_nuid = parse_card_uid(hex("000401020304aabbccdd"), CardUidRequest::with_nuid);
        expect(uid_and_nuid && uid_and_nuid.value().uid == hex("01020304") &&
                   uid_and_nuid.value().nuid ==
                       std::optional<std::array<Byte, 4>>{{0xAA, 0xBB, 0xCC, 0xDD}},
               "explicit NUID response separates the four-byte suffix from a prefixed UID");
        auto seven_uid_and_nuid =
            parse_card_uid(hex("04010203040506aabbccdd"), CardUidRequest::with_nuid);
        expect(seven_uid_and_nuid && seven_uid_and_nuid.value().uid == hex("04010203040506") &&
                   seven_uid_and_nuid.value().nuid,
               "explicit NUID response accepts the bare seven-byte UID form");
        expect(static_cast<bool>(parse_card_uid(hex("000a00010203040506070809aabbccdd"),
                                                CardUidRequest::with_nuid)),
               "explicit NUID response accepts the prefixed ten-byte UID form");
        expect(!parse_card_uid(hex("04010203040506"), CardUidRequest::with_nuid),
               "requested NUID suffix cannot be omitted");
        expect(!parse_card_uid(hex("04010203040506aabbccdd"), CardUidRequest::without_nuid),
               "unrequested NUID suffix is rejected");
        expect(!parse_card_uid(hex("000401020304aabbccdd"), CardUidRequest::omit_option),
               "option-omitted UID response rejects an unexpected NUID suffix");
        expect(!parse_card_uid(hex("000501020304aabbccdd"), CardUidRequest::with_nuid),
               "NUID response still validates the UID format prefix");
        expect(static_cast<bool>(parse_originality_signature(Bytes(56, 0x5A))),
               "56-byte signature accepted for separate verification");
        expect(!parse_originality_signature(Bytes(55)), "truncated signature rejected");
    }

    /** @brief Verify configuration and transaction requests against stable literal fields. */
    void check_management_and_configuration() {
        auto original = abort_transaction();
        Command moved(std::move(original.value()));
        expect(moved.valid() && !original.value().valid(),
               "ownership transfer invalidates the source command before it can be executed");
        expect_command(commit_transaction(), 0xC7, "");
        expect_command(commit_transaction(true), 0xC7, "01");
        expect_command(abort_transaction(), 0xA7, "");
        expect_command(commit_reader_id(hex("000102030405060708090a0b0c0d0e0f")), 0xC8,
                       "000102030405060708090a0b0c0d0e0f");
        expect(!commit_reader_id(Bytes(15)), "reader ID must have sixteen bytes");
        expect_command(get_card_uid(), 0x51, "");
        auto explicit_uid = get_card_uid(CardUidRequest::without_nuid);
        expect_command(explicit_uid, 0x51, "00");
        expect(explicit_uid.value().minimum_response() == 6 &&
                   explicit_uid.value().maximum_response() == 12,
               "explicit UID-only request accepts only documented UID response lengths");
        auto explicit_nuid = get_card_uid(CardUidRequest::with_nuid);
        expect_command(explicit_nuid, 0x51, "01");
        expect(explicit_nuid.value().minimum_response() == 10 &&
                   explicit_nuid.value().maximum_response() == 16,
               "NUID request accounts for the exact four-byte response suffix");
        auto invalid_uid_request = get_card_uid(static_cast<CardUidRequest>(0x7F));
        expect(!invalid_uid_request &&
                   invalid_uid_request.error().code == ErrorCode::invalid_argument &&
                   invalid_uid_request.error().outcome == Outcome::not_sent,
               "unknown GetCardUID request variant fails before I/O");
        auto signature = read_originality_signature();
        expect_command(signature, 0x3C, "00");
        expect(!signature.value().requires_authentication() &&
                   signature.value().response_mode() == CommunicationMode::full,
               "signature uses full response under authentication and permits plain otherwise");
        expect_command(format_picc(), 0xFC, "");
        PiccConfiguration picc;
        picc.random_identifier = true;
        picc.proximity_check_mandatory = true;
        picc.error_code_binding = true;
        expect_command(set_picc_configuration(picc), 0x5C, "00", "16");
        expect_command(set_capability_configuration({{1, 2, 3, 4, 5, 6, 7, 8, 9}}), 0x5C, "05",
                       "010203040506070809");
        expect_command(set_default_aes_key(hex("000102030405060708090a0b0c0d0e0f"), 7), 0x5C, "01",
                       "000102030405060708090a0b0c0d0e0f000000000000000007");
        expect_command(set_ats(hex("0278")), 0x5C, "02", "0278");
        expect(!set_ats(hex("0378")), "ATS length byte must match actual data");
        expect_command(set_atqa(0x0344), 0x5C, "0c", "4403");

        FileSettingsChange change{number<FileNumber>(1)};
        change.communication = CommunicationMode::mac;
        change.access = AccessRights{1, 2, 3, 4};
        change.additional_access = {{5, 6, 7, 8}};
        expect_command(change_file_settings(change), 0x5F, "01", "811234015678");
        change.additional_access.clear();
        change.transaction_counter_limit = 0x12345678;
        expect_command(change_file_settings(change), 0x5F, "01", "21123478563412");
    }

} // namespace

/** @brief Run independent EV3 field and parser checks; return process success only if all pass. */
int main() {
    check_application_commands();
    check_delegated_application_commands();
    check_file_creation();
    check_data_commands();
    check_key_management();
    check_response_parsers();
    check_management_and_configuration();
    std::cout << "EV3 command codec tests passed.\n";
    return EXIT_SUCCESS;
}
