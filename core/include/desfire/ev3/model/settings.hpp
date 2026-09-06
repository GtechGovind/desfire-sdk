/**
 * @file settings.hpp
 * @brief Owned DESFire EV3 application, key, file, and PICC configuration models.
 */
#pragma once

#include "communication.hpp"
#include "identifiers.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace desfire::ev3::model {

    /** @brief Optional application key-set fields in native command order. */
    struct KeySetConfiguration final {
        Byte active_version{};     ///< Version assigned to the initially active key set.
        Byte number_of_sets{2};    ///< Total key sets, validated by the checked builder.
        Byte maximum_key_size{16}; ///< Maximum application key width in bytes.
        Byte settings{};           ///< Documented key-set settings byte.
    };

    /** @brief AES application creation settings with typed optional extensions. */
    struct ApplicationConfiguration final {
        ApplicationId id;                              ///< Nonzero application identifier.
        Byte key_settings{0x0F};                       ///< Native application key-settings byte.
        Byte number_of_keys{1};                        ///< Application key count and AES type bits.
        bool iso_file_identifiers{};                   ///< Enable ISO file identifiers.
        std::optional<Byte> key_settings3{};           ///< Optional third key-settings byte.
        std::optional<KeySetConfiguration> key_sets{}; ///< Optional key-set configuration.
        std::optional<std::uint16_t> iso_id{};         ///< Optional big-endian ISO DF identifier.
        Bytes df_name{}; ///< Optional one-through-sixteen-byte DF name.
    };

    /** @brief Metadata required to create one delegated AES application. */
    struct DelegatedApplicationConfiguration final {
        ApplicationConfiguration application; ///< Application fields authenticated by DAM MAC.
        std::uint16_t slot{};                 ///< Delegated application slot number.
        Byte slot_version{};                  ///< Required slot version.
        std::uint16_t quota_limit{};          ///< Delegated storage quota limit.
    };

    /** @brief Decoded selected-application key settings. */
    struct KeySettings final {
        Byte settings{};                                      ///< First key-settings byte.
        Byte key_type_and_count{};                            ///< Key type and key count byte.
        std::optional<std::array<Byte, 4>> key_set_details{}; ///< Optional key-set detail bytes.
    };

    /** @brief Four access selectors: keys 0..13, free access 14, or denied 15. */
    struct AccessRights final {
        Byte read_write{15}; ///< Combined read/write access selector.
        Byte change{15};     ///< Change-settings access selector.
        Byte read{15};       ///< Read access selector.
        Byte write{15};      ///< Write access selector.

        /**
         * @brief Compare all access selectors.
         * @return True when every selector is equal; false otherwise.
         */
        bool operator==(const AccessRights&) const = default;
    };

    /** @brief Native file types returned by GetFileSettings. */
    enum class FileType : Byte {
        standard_data = 0,
        backup_data = 1,
        value = 2,
        linear_record = 3,
        cyclic_record = 4,
        transaction_mac = 5
    };

    /** @brief Standard or backup data-file creation settings. */
    struct DataFileConfiguration final {
        FileNumber file;                                           ///< Native file number.
        ByteCount size;                                            ///< File size in bytes.
        CommunicationMode communication{CommunicationMode::plain}; ///< Protection mode.
        AccessRights access{};                 ///< Four primary access selectors.
        std::optional<std::uint16_t> iso_id{}; ///< Optional ISO EF identifier.
        bool backup{};                         ///< Create a transactional backup file.
        bool additional_access_rights{};       ///< Enable additional access-right records.
    };

    /** @brief Signed value-file limits, initial value, and access settings. */
    struct ValueFileConfiguration final {
        FileNumber file;                                          ///< Native file number.
        std::int32_t lower_limit{};                               ///< Inclusive lower value bound.
        std::int32_t upper_limit{};                               ///< Inclusive upper value bound.
        std::int32_t initial_value{};                             ///< Initial stored value.
        CommunicationMode communication{CommunicationMode::full}; ///< Protection mode.
        AccessRights access{};         ///< Four primary access selectors.
        bool limited_credit_enabled{}; ///< Enable LimitedCredit.
        bool free_get_value{};         ///< Permit unauthenticated GetValue when card policy allows.
        bool additional_access_rights{}; ///< Enable additional access-right records.
    };

    /** @brief Linear or cyclic record-file creation settings. */
    struct RecordFileConfiguration final {
        FileNumber file;                                           ///< Native file number.
        ByteCount record_size;                                     ///< Bytes in each record.
        ByteCount maximum_records;                                 ///< Maximum stored record count.
        CommunicationMode communication{CommunicationMode::plain}; ///< Protection mode.
        AccessRights access{};                 ///< Four primary access selectors.
        std::optional<std::uint16_t> iso_id{}; ///< Optional ISO EF identifier.
        bool cyclic{};                         ///< Create cyclic rather than linear storage.
        bool additional_access_rights{};       ///< Enable additional access-right records.
    };

    /** @brief Decoded data-file size. */
    struct DataFileSettings final {
        std::uint32_t size{}; ///< File size in bytes.
    };

    /** @brief Decoded value-file limits and flags. */
    struct ValueFileSettings final {
        std::int32_t lower_limit{};          ///< Inclusive lower bound.
        std::int32_t upper_limit{};          ///< Inclusive upper bound.
        std::int32_t limited_credit_value{}; ///< Current limited-credit value.
        bool limited_credit_enabled{};       ///< LimitedCredit enabled flag.
        bool free_get_value{};               ///< Free GetValue enabled flag.
    };

    /** @brief Decoded record-file dimensions and current record count. */
    struct RecordFileSettings final {
        std::uint32_t record_size{};     ///< Bytes per record.
        std::uint32_t maximum_records{}; ///< Maximum record count.
        std::uint32_t current_records{}; ///< Current record count.
    };

    /** @brief Decoded transaction-MAC file key option and version. */
    struct TransactionMacFileSettings final {
        Byte key_option{};  ///< Transaction-MAC key option byte.
        Byte key_version{}; ///< Transaction-MAC key version.
    };

    /** @brief Strictly decoded file settings and supported optional extensions. */
    struct FileSettings final {
        FileType type{};                   ///< Native file type.
        CommunicationMode communication{}; ///< File communication mode.
        Byte options{};                    ///< Complete transmitted file-option byte.
        AccessRights access{};             ///< Primary access rights.
        std::variant<DataFileSettings, ValueFileSettings, RecordFileSettings,
                     TransactionMacFileSettings>
            details{};                                 ///< File-type-specific fields.
        std::vector<AccessRights> additional_access{}; ///< Additional access-right records.
        std::optional<std::uint32_t> transaction_counter_limit{}; ///< Optional counter limit.
    };

    /** @brief Mutable ChangeFileSettings fields independent of file dimensions. */
    struct FileSettingsChange final {
        FileNumber file; ///< File whose settings are changed.
        CommunicationMode communication{CommunicationMode::plain}; ///< New file mode.
        AccessRights access{};                                     ///< New primary access rights.
        std::vector<AccessRights> additional_access{};             ///< New additional rights.
        std::optional<std::uint32_t> transaction_counter_limit{};  ///< Optional counter limit.
        CommunicationMode command_communication{CommunicationMode::full}; ///< Command mode.
    };

    /** @brief PICC configuration flags named according to supplied NXP documentation. */
    struct PiccConfiguration final {
        bool disable_format{};                        ///< Disable future FormatPICC operations.
        bool random_identifier{};                     ///< Enable random identifier behavior.
        bool proximity_check_mandatory{};             ///< Require proximity checks.
        bool virtual_card_authentication_mandatory{}; ///< Require virtual-card authentication.
        bool error_code_binding{};                    ///< Enable error-code binding.
        bool random_identifier_configuration{};       ///< Permit random-ID configuration.
        bool four_byte_nuid_configuration{};          ///< Permit four-byte NUID configuration.
    };

    /** @brief Exact nine-byte card capability configuration in command order. */
    struct CapabilityConfiguration final {
        std::array<Byte, 9> data{}; ///< Caller-supplied documented capability bytes.
    };

} // namespace desfire::ev3::model
