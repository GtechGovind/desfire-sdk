/**
 * @file keys.hpp
 * @brief Checked DESFire EV3 AES key and key-set management commands.
 */
#pragma once

#include "command.hpp"
#include <desfire/ev3/model/settings.hpp>

#include <optional>

namespace desfire::ev3::native::checked {

    /**
     * @brief Decode the complete two- or six-byte key-settings response.
     * @param payload Complete status-free response data.
     * @return Parsed key settings or malformed_response.
     */
    Result<model::KeySettings> parse_key_settings(ByteView payload);

    /** @brief Build GetKeySettings with management-command protection policy. */
    Result<Command> get_key_settings();

    /** @brief Build authenticated ChangeKeySettings. */
    Result<Command> change_key_settings(Byte settings);

    /** @brief Build GetKeyVersion with an optional key-set selector. */
    Result<Command> get_key_version(model::KeyNumber key, std::optional<Byte> key_set = {});

    /** @brief Build GetKeySetVersions with bounded response length. */
    Result<Command> get_key_set_versions();

    /**
     * @brief Build the AES ChangeKey payload for a current or different authenticated key.
     * @param key Target native key number.
     * @param new_key Exact sixteen-byte replacement AES key.
     * @param version Replacement key version.
     * @param authenticated_key Key used for the current native authentication.
     * @param old_key Exact sixteen-byte old key when protocol XOR and CRC protection requires it.
     * @param key_set Optional key-set selector.
     * @param picc_master_key True only for PICC master-key semantics.
     * @return Checked encrypted-data command or pre-I/O validation failure.
     */
    Result<Command> change_aes_key(model::KeyNumber key, ByteView new_key, Byte version,
                                   model::KeyNumber authenticated_key, ByteView old_key = {},
                                   std::optional<Byte> key_set = {}, bool picc_master_key = false);

    /** @brief Build EV2 InitializeKeySet. */
    Result<Command> initialize_key_set(Byte key_set);

    /** @brief Build EV2 FinalizeKeySet. */
    Result<Command> finalize_key_set(Byte key_set, Byte version);

    /** @brief Build EV2 RollKeySet. */
    Result<Command> roll_key_set(Byte key_set);

} // namespace desfire::ev3::native::checked
