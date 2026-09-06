/**
 * @file applications.hpp
 * @brief Checked DESFire EV3 application-management commands and response models.
 */
#pragma once

#include "command.hpp"
#include <desfire/ev3/model/settings.hpp>

#include <cstdint>
#include <vector>

namespace desfire::ev3::native::checked {

    /** @brief Decoded eight-byte delegated-application information response. */
    struct DelegatedApplicationInfo final {
        Byte slot_version{};              ///< Current delegated slot version.
        std::uint16_t quota_limit{};      ///< Configured delegated quota.
        std::uint16_t free_blocks{};      ///< Remaining delegated blocks.
        model::ApplicationId application; ///< Assigned application identifier.
    };

    /** @brief One GetDFNames response record whose physical frame boundary is significant. */
    struct DfName final {
        model::ApplicationId application; ///< Native application identifier.
        std::uint16_t iso_id{};           ///< Big-endian ISO DF identifier.
        Bytes name{};                     ///< Owned DF name bytes.
    };

    /**
     * @brief Decode unique nonzero three-byte application identifiers.
     * @param payload Complete status-free response data.
     * @return Parsed identifiers or malformed_response.
     */
    Result<std::vector<model::ApplicationId>> parse_application_ids(ByteView payload);

    /**
     * @brief Decode unique little-endian ISO file identifiers.
     * @param payload Complete status-free response data.
     * @return Parsed ISO identifiers or malformed_response.
     */
    Result<std::vector<std::uint16_t>> parse_iso_file_ids(ByteView payload);

    /**
     * @brief Decode one frame-preserving DF-name record.
     * @param payload One physical response frame without status.
     * @return Parsed record or malformed_response.
     */
    Result<DfName> parse_df_name_frame(ByteView payload);

    /**
     * @brief Decode one exact delegated-application information response.
     * @param payload Exact eight-byte status-free response.
     * @return Parsed delegated metadata or malformed_response.
     */
    Result<DelegatedApplicationInfo> parse_delegated_application_info(ByteView payload);

    /** @brief Build GetApplicationIDs with management-command protection policy. */
    Result<Command> get_application_ids();

    /** @brief Build GetDFNames; callers must preserve each response frame separately. */
    Result<Command> get_df_names();

    /** @brief Build GetISOFileIDs with bounded response length. */
    Result<Command> get_iso_file_ids();

    /** @brief Build checked AES application creation. */
    Result<Command> create_application(const model::ApplicationConfiguration& configuration);

    /** @brief Build checked two-frame delegated AES application creation. */
    Result<Command>
    create_delegated_application(const model::DelegatedApplicationConfiguration& configuration,
                                 ByteView encrypted_default_key, ByteView dam_mac);

    /** @brief Build delegated-application slot query. */
    Result<Command> get_delegated_application_info(std::uint16_t slot);

    /** @brief Build native application deletion. */
    Result<Command> delete_application(model::ApplicationId id);

    /** @brief Build delegated application deletion with an eight-byte issuer MAC. */
    Result<Command> delete_delegated_application(model::ApplicationId id, ByteView dam_mac);

} // namespace desfire::ev3::native::checked
