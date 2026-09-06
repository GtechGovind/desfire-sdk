/**
 * @file files.hpp
 * @brief Checked DESFire EV3 file-management and data commands.
 */
#pragma once

#include "command.hpp"
#include <desfire/ev3/model/settings.hpp>

#include <array>

namespace desfire::ev3::native::checked {

    /** @brief GetFileCounters response with its reserved bytes preserved. */
    struct FileCounters final {
        std::uint32_t sdm_read_counter{}; ///< Three-byte little-endian SDM read counter.
        std::array<Byte, 2> reserved{};   ///< Two transmitted reserved bytes.
    };

    /**
     * @brief Decode a complete file-settings response; unverified SDM layouts fail closed.
     * @param payload Complete status-free response bytes.
     * @return Strict file settings or malformed_response/unsupported evidence.
     */
    Result<model::FileSettings> parse_file_settings(ByteView payload);

    /**
     * @brief Decode exactly three counter bytes and two reserved bytes.
     * @param payload Exact five-byte status-free response.
     * @return Parsed counters or malformed_response.
     */
    Result<FileCounters> parse_file_counters(ByteView payload);

    /** @brief Build GetFileIDs with a maximum of 32 returned identifiers. */
    Result<Command> get_file_ids();

    /** @brief Build standard or backup data-file creation. */
    Result<Command> create_data_file(const model::DataFileConfiguration& configuration);

    /** @brief Build value-file creation after validating limits and flags. */
    Result<Command> create_value_file(const model::ValueFileConfiguration& configuration);

    /** @brief Build linear or cyclic record-file creation. */
    Result<Command> create_record_file(const model::RecordFileConfiguration& configuration);

    /** @brief Build transaction-MAC file creation with an AES-128 key. */
    Result<Command> create_transaction_mac_file(model::FileNumber file, model::AccessRights access,
                                                ByteView aes_key, Byte key_version);

    /** @brief Build file deletion. */
    Result<Command> delete_file(model::FileNumber file);

    /** @brief Build GetFileSettings with a bounded response. */
    Result<Command> get_file_settings(model::FileNumber file);

    /** @brief Build GetFileCounters for Plain or Full communication. */
    Result<Command> get_file_counters(model::FileNumber file,
                                      model::CommunicationMode communication);

    /** @brief Build ChangeFileSettings; SDM encoding remains fail-closed. */
    Result<Command> change_file_settings(const model::FileSettingsChange& configuration);

    /** @brief Build bounded native data read. */
    Result<Command> read_data(model::FileNumber file, model::Offset offset, model::ByteCount length,
                              model::CommunicationMode communication);

    /** @brief Build native data write with owned sensitive payload. */
    Result<Command> write_data(model::FileNumber file, model::Offset offset, ByteView data,
                               model::CommunicationMode communication);

    /** @brief Build bounded native record read. */
    Result<Command> read_records(model::FileNumber file, model::Offset first_record,
                                 model::ByteCount count, model::CommunicationMode communication,
                                 std::size_t maximum_response = 16U * 1024U * 1024U);

    /** @brief Build native record append/write. */
    Result<Command> write_record(model::FileNumber file, model::Offset offset, ByteView data,
                                 model::CommunicationMode communication);

    /** @brief Build native record update at a record and byte offset. */
    Result<Command> update_record(model::FileNumber file, model::Offset record,
                                  model::Offset offset, ByteView data,
                                  model::CommunicationMode communication);

    /** @brief Build transactional clearing of a record file. */
    Result<Command> clear_record_file(model::FileNumber file);

} // namespace desfire::ev3::native::checked
