/**
 * @file files.cpp
 * @brief Checked native file-command construction and response decoding.
 */
#include "detail/command_support.hpp"
#include <desfire/ev3/native/checked/files.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <set>

namespace desfire::ev3::native::checked {

    using namespace detail;

    /** @brief Implement `parse_file_settings` to decode a bounded native file-settings response. */
    Result<model::FileSettings> parse_file_settings(ByteView payload) {
        if (payload.size() < 4 || payload.size() > 128 || payload[0] > 5) {
            return malformed("EV3 file settings have an invalid prefix or length");
        }
        model::FileSettings settings;
        settings.type = static_cast<model::FileType>(payload[0]);
        settings.options = payload[1];
        settings.communication = static_cast<model::CommunicationMode>(payload[1] & 3U);
        settings.access = read_access(payload.subspan(2, 2));
        if (!valid_mode(settings.communication) || (settings.options & 0x1CU) != 0) {
            return malformed("EV3 file settings contain reserved option bits");
        }
        std::size_t consumed = 4;
        switch (settings.type) {
        case model::FileType::standard_data:
        case model::FileType::backup_data:
            if (payload.size() < 7) {
                return malformed("EV3 data-file settings are truncated");
            }
            settings.details = model::DataFileSettings{get_le(payload.subspan(4, 3))};
            consumed = 7;
            break;
        case model::FileType::value:
            if (payload.size() < 17 || (payload[16] & 0xFCU) != 0) {
                return malformed("EV3 value-file settings are truncated or have invalid flags");
            }
            settings.details = model::ValueFileSettings{
                std::bit_cast<std::int32_t>(get_le(payload.subspan(4, 4))),
                std::bit_cast<std::int32_t>(get_le(payload.subspan(8, 4))),
                std::bit_cast<std::int32_t>(get_le(payload.subspan(12, 4))),
                (payload[16] & 1U) != 0, (payload[16] & 2U) != 0};
            consumed = 17;
            break;
        case model::FileType::linear_record:
        case model::FileType::cyclic_record:
            if (payload.size() < 13) {
                return malformed("EV3 record-file settings are truncated");
            }
            settings.details = model::RecordFileSettings{get_le(payload.subspan(4, 3)),
                                                         get_le(payload.subspan(7, 3)),
                                                         get_le(payload.subspan(10, 3))};
            consumed = 13;
            break;
        case model::FileType::transaction_mac:
            if (payload.size() < 6) {
                return malformed("EV3 transaction-MAC settings are truncated");
            }
            settings.details = model::TransactionMacFileSettings{payload[4], payload[5]};
            consumed = 6;
            break;
        }

        if ((settings.options & 0x80U) != 0) {
            if (consumed == payload.size()) {
                return malformed("EV3 additional access-right count is absent");
            }
            const Byte count = payload[consumed++];
            if (count > 7 || payload.size() - consumed < static_cast<std::size_t>(count) * 2) {
                return malformed("EV3 additional access rights are truncated or exceed seven");
            }
            for (Byte index = 0; index < count; ++index) {
                settings.additional_access.push_back(read_access(payload.subspan(consumed, 2)));
                consumed += 2;
            }
        }
        if ((settings.options & 0x40U) != 0) {
            return Error{ErrorCode::unsupported,
                         "EV3 SDM settings require the verified device-specific conditional layout",
                         Outcome::succeeded};
        }
        if ((settings.options & 0x20U) != 0) {
            if (settings.type != model::FileType::transaction_mac ||
                payload.size() - consumed < 4) {
                return malformed("EV3 transaction-counter limit has an invalid layout");
            }
            settings.transaction_counter_limit = get_le(payload.subspan(consumed, 4));
            consumed += 4;
        }
        if (consumed != payload.size()) {
            return malformed("EV3 file settings contain unexpected trailing bytes");
        }
        return settings;
    }

    /** @brief Implement `parse_file_counters` to decode an exact native file-counter response. */
    Result<FileCounters> parse_file_counters(ByteView payload) {
        if (payload.size() != 5) {
            return malformed(
                "EV3 file counter response requires three counter and two reserved bytes");
        }
        return FileCounters{get_le(payload.first(3)), {payload[3], payload[4]}};
    }

    /** @brief Implement `get_file_ids` to build the bounded GetFileIDs command. */
    Result<Command> get_file_ids() {
        return management(0x6F, {}, 0, 32).build();
    }

    /** @brief Implement `create_data_file` to build standard or backup data-file creation. */
    Result<Command> create_data_file(const model::DataFileConfiguration& settings) {
        if (!valid_mode(settings.communication) || !valid_access(settings.access) ||
            settings.size.value() == 0) {
            return invalid("Invalid EV3 data-file communication, access rights, or size");
        }
        Bytes header = file_creation_prefix(settings.file, settings.iso_id);
        Byte options = static_cast<Byte>(settings.communication);
        if (settings.additional_access_rights) {
            options |= 0x80U;
        }
        header.push_back(options);
        append_access(header, settings.access);
        put_le(header, settings.size.value(), 3);
        Byte opcode = 0xCD;
        if (settings.backup) {
            opcode = 0xCB;
        }
        return management(opcode, std::move(header)).build();
    }

    /** @brief Implement `create_value_file` to build value-file creation after validating limits.
     */
    Result<Command> create_value_file(const model::ValueFileConfiguration& settings) {
        if (!valid_mode(settings.communication) || !valid_access(settings.access) ||
            settings.lower_limit > settings.upper_limit ||
            settings.initial_value < settings.lower_limit ||
            settings.initial_value > settings.upper_limit) {
            return invalid("Invalid EV3 value-file communication, access rights, or limits");
        }
        Byte options = static_cast<Byte>(settings.communication);
        if (settings.additional_access_rights) {
            options |= 0x80U;
        }
        Bytes header{static_cast<Byte>(settings.file.value()), options};
        append_access(header, settings.access);
        put_le(header, std::bit_cast<std::uint32_t>(settings.lower_limit), 4);
        put_le(header, std::bit_cast<std::uint32_t>(settings.upper_limit), 4);
        put_le(header, std::bit_cast<std::uint32_t>(settings.initial_value), 4);
        Byte limited_options = 0;
        if (settings.limited_credit_enabled) {
            limited_options |= 1U;
        }
        if (settings.free_get_value) {
            limited_options |= 2U;
        }
        header.push_back(limited_options);
        return management(0xCC, std::move(header)).build();
    }

    /** @brief Implement `create_record_file` to build linear or cyclic record-file creation. */
    Result<Command> create_record_file(const model::RecordFileConfiguration& settings) {
        if (!valid_mode(settings.communication) || !valid_access(settings.access) ||
            settings.record_size.value() == 0 || settings.maximum_records.value() == 0) {
            return invalid("Invalid EV3 record-file communication, access rights, or dimensions");
        }
        Bytes header = file_creation_prefix(settings.file, settings.iso_id);
        Byte options = static_cast<Byte>(settings.communication);
        if (settings.additional_access_rights) {
            options |= 0x80U;
        }
        header.push_back(options);
        append_access(header, settings.access);
        put_le(header, settings.record_size.value(), 3);
        put_le(header, settings.maximum_records.value(), 3);
        Byte opcode = 0xC1;
        if (settings.cyclic) {
            opcode = 0xC0;
        }
        return management(opcode, std::move(header)).build();
    }

    /** @brief Implement `create_transaction_mac_file` to build transaction-MAC file creation with
     * AES key material. */
    Result<Command> create_transaction_mac_file(model::FileNumber file, model::AccessRights access,
                                                ByteView aes_key, Byte key_version) {
        if (!valid_access(access) || aes_key.size() != 16) {
            return invalid("Transaction MAC file requires valid access rights and an AES key");
        }
        Bytes header{static_cast<Byte>(file.value()), 0x00};
        append_access(header, access);
        header.push_back(0x02);
        SecureBuffer data(17);
        std::copy(aes_key.begin(), aes_key.end(), data.mutable_view().begin());
        data.mutable_view()[16] = key_version;
        detail::CommandBuilder command = management(0xCE, std::move(header));
        command.data = std::move(data);
        command.request_mode = model::CommunicationMode::full;
        command.requires_authentication = true;
        return command.build();
    }

    /** @brief Implement `delete_file` to build a checked file-deletion command. */
    Result<Command> delete_file(model::FileNumber file) {
        return management(0xDF, {static_cast<Byte>(file.value())}).build();
    }

    /** @brief Implement `get_file_settings` to build bounded file-settings retrieval. */
    Result<Command> get_file_settings(model::FileNumber file) {
        return management(0xF5, {static_cast<Byte>(file.value())}, 6, 128).build();
    }

    /** @brief Implement `get_file_counters` to build protected file-counter retrieval. */
    Result<Command> get_file_counters(model::FileNumber file, model::CommunicationMode mode) {
        if (mode == model::CommunicationMode::mac) {
            return invalid("GetFileCounters supports plain or fully enciphered responses");
        }
        return file_command(0xF6, {static_cast<Byte>(file.value())}, {}, mode, true, 5, 5);
    }

    /** @brief Implement `change_file_settings` to build checked file-settings mutation. */
    Result<Command> change_file_settings(const model::FileSettingsChange& settings) {
        if (!valid_mode(settings.communication) || !valid_access(settings.access) ||
            settings.additional_access.size() > 7) {
            return invalid("Invalid EV3 file mode, access rights, or additional rights count");
        }
        Byte options = static_cast<Byte>(settings.communication);
        if (!settings.additional_access.empty()) {
            options |= 0x80U;
        }
        if (settings.transaction_counter_limit) {
            options |= 0x20U;
        }
        Bytes data{options};
        append_access(data, settings.access);
        if (!settings.additional_access.empty()) {
            data.push_back(static_cast<Byte>(settings.additional_access.size()));
            for (const auto& access : settings.additional_access) {
                if (!valid_access(access)) {
                    return invalid("Invalid EV3 additional access-right selector");
                }
                append_access(data, access);
            }
        }
        if (settings.transaction_counter_limit) {
            put_le(data, *settings.transaction_counter_limit, 4);
        }
        return file_command(0x5F, {static_cast<Byte>(settings.file.value())}, data,
                            settings.command_communication, false);
    }

    /** @brief Implement the documented bounded data-read command builder. */
    Result<Command> read_data(model::FileNumber file, model::Offset offset, model::ByteCount length,
                              model::CommunicationMode mode) {
        if (!valid_range(offset, length.value())) {
            return invalid("EV3 read range exceeds the three-byte address space");
        }
        std::size_t minimum = length.value();
        std::size_t maximum = length.value();
        if (length.value() == 0) {
            maximum = maximum_three_byte - offset.value();
        }
        return file_command(0xBD, range_header(file, offset, length.value()), {}, mode, true,
                            minimum, maximum);
    }

    /** @brief Implement the documented data-write command builder. */
    Result<Command> write_data(model::FileNumber file, model::Offset offset, ByteView data,
                               model::CommunicationMode mode) {
        if (data.empty() || !valid_range(offset, data.size())) {
            return invalid("EV3 write requires a nonempty in-range payload");
        }
        return file_command(0x3D,
                            range_header(file, offset, static_cast<std::uint32_t>(data.size())),
                            data, mode, false);
    }

    /** @brief Implement the documented bounded record-read command builder. */
    Result<Command> read_records(model::FileNumber file, model::Offset first_record,
                                 model::ByteCount count, model::CommunicationMode mode,
                                 std::size_t maximum_response) {
        if (!valid_range(first_record, count.value()) || maximum_response == 0 ||
            maximum_response > maximum_logical_response) {
            return invalid("Invalid EV3 record range or response bound");
        }
        return file_command(0xBB, range_header(file, first_record, count.value()), {}, mode, true,
                            0, maximum_response);
    }

    /** @brief Implement the documented record-write command builder. */
    Result<Command> write_record(model::FileNumber file, model::Offset offset, ByteView data,
                                 model::CommunicationMode mode) {
        if (data.empty() || !valid_range(offset, data.size())) {
            return invalid("EV3 record write requires a nonempty in-range payload");
        }
        return file_command(0x3B,
                            range_header(file, offset, static_cast<std::uint32_t>(data.size())),
                            data, mode, false);
    }

    /** @brief Implement `update_record` to build a native record update. */
    Result<Command> update_record(model::FileNumber file, model::Offset record,
                                  model::Offset offset, ByteView data,
                                  model::CommunicationMode mode) {
        if (data.empty() || !valid_range(offset, data.size())) {
            return invalid("EV3 record update requires a nonempty in-range payload");
        }
        Bytes header{static_cast<Byte>(file.value())};
        put_le(header, record.value(), 3);
        put_le(header, offset.value(), 3);
        put_le(header, static_cast<std::uint32_t>(data.size()), 3);
        return file_command(0xDB, std::move(header), data, mode, false);
    }

    /** @brief Implement `clear_record_file` to build transactional record-file clearing. */
    Result<Command> clear_record_file(model::FileNumber file) {
        return management(0xEB, {static_cast<Byte>(file.value())}).build();
    }

} // namespace desfire::ev3::native::checked
