/**
 * @file keys.cpp
 * @brief Checked native key-command construction and response decoding.
 */
#include "detail/command_support.hpp"
#include <desfire/ev3/native/checked/keys.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <set>

namespace desfire::ev3::native::checked {

    using namespace detail;

    /** @brief Implement `parse_key_settings` to decode an exact key-settings response. */
    Result<model::KeySettings> parse_key_settings(ByteView payload) {
        if (payload.size() != 2 && payload.size() != 6) {
            return malformed("EV3 key settings must contain two or six bytes");
        }
        model::KeySettings settings{payload[0], payload[1], {}};
        if (payload.size() == 6) {
            std::array<Byte, 4> details{};
            std::copy(payload.begin() + 2, payload.end(), details.begin());
            settings.key_set_details = details;
        }
        return settings;
    }

    /** @brief Implement `get_key_settings` to build current key-settings retrieval. */
    Result<Command> get_key_settings() {
        return management(0x45, {}, 2, 6).build();
    }

    /** @brief Implement `change_key_settings` to build protected key-settings mutation. */
    Result<Command> change_key_settings(Byte settings) {
        const std::array<Byte, 1> data{settings};
        return file_command(0x54, {}, data, model::CommunicationMode::full, false);
    }

    /** @brief Implement `get_key_version` to build one key-version query. */
    Result<Command> get_key_version(model::KeyNumber key, std::optional<Byte> key_set) {
        Bytes header{static_cast<Byte>(key.value())};
        if (key_set) {
            if (*key_set > 15 || key.value() > 13) {
                return invalid("Application key version requires key 0..13 and set 0..15");
            }
            header[0] |= 0x40U;
            header.push_back(*key_set);
        }
        return management(0x64, std::move(header), 1, 1).build();
    }

    /** @brief Implement `get_key_set_versions` to build bounded key-set version retrieval. */
    Result<Command> get_key_set_versions() {
        return management(0x64, {0x40, 0x80}, 2, 16).build();
    }

    /** @brief Implement the documented AES ChangeKey command builder. */
    Result<Command> change_aes_key(model::KeyNumber key, ByteView new_key, Byte version,
                                   model::KeyNumber authenticated_key, ByteView old_key,
                                   std::optional<Byte> key_set, bool picc_master_key) {
        if (new_key.size() != 16 || (key_set && *key_set > 15) ||
            (picc_master_key && key.value() != 0)) {
            return invalid("Invalid AES key length, key set, or PICC master key selector");
        }
        const bool changes_current_key = key == authenticated_key && key_set.value_or(0) == 0;
        if ((changes_current_key && !old_key.empty()) ||
            (!changes_current_key && old_key.size() != 16)) {
            return invalid("Old AES key is required only when changing another key or key set");
        }
        Bytes header;
        Byte opcode = 0xC4;
        if (key_set) {
            opcode = 0xC6;
            header.push_back(*key_set);
        }
        Byte selector = static_cast<Byte>(key.value());
        if (picc_master_key) {
            selector |= 0x80U;
        }
        header.push_back(selector);
        SecureBuffer data(changes_current_key ? 17 : 21);
        auto writable = data.mutable_view();
        for (std::size_t index = 0; index < 16; ++index) {
            writable[index] = new_key[index];
            if (!changes_current_key) {
                writable[index] ^= old_key[index];
            }
        }
        writable[16] = version;
        if (!changes_current_key) {
            const std::uint32_t checksum = crc32(new_key);
            for (std::size_t index = 0; index < 4; ++index) {
                writable[17 + index] = static_cast<Byte>(checksum >> (index * 8));
            }
        }
        detail::CommandBuilder command = management(opcode, std::move(header));
        command.data = std::move(data);
        command.request_mode = model::CommunicationMode::full;
        command.requires_authentication = true;
        command.invalidates_session = changes_current_key;
        command.current_authenticated_key = static_cast<Byte>(authenticated_key.value());
        if (changes_current_key) {
            command.response_mode = model::CommunicationMode::plain;
        }
        return command.build();
    }

    /** @brief Implement `initialize_key_set` to build EV2 key-set initialization. */
    Result<Command> initialize_key_set(Byte key_set) {
        if (key_set > 15) {
            return invalid("EV3 key-set number exceeds 15");
        }
        detail::CommandBuilder command = management(0x56);
        command.data = SecureBuffer(Bytes{key_set, 0x02});
        command.requires_authentication = true;
        return command.build();
    }

    /** @brief Implement `finalize_key_set` to build EV2 key-set finalization. */
    Result<Command> finalize_key_set(Byte key_set, Byte version) {
        if (key_set > 15) {
            return invalid("EV3 key-set number exceeds 15");
        }
        detail::CommandBuilder command = management(0x57);
        command.data = SecureBuffer(Bytes{key_set, version});
        command.requires_authentication = true;
        return command.build();
    }

    /** @brief Implement `roll_key_set` to build EV2 key-set activation. */
    Result<Command> roll_key_set(Byte key_set) {
        if (key_set > 15) {
            return invalid("EV3 key-set number exceeds 15");
        }
        detail::CommandBuilder command = management(0x55);
        command.data = SecureBuffer(Bytes{key_set});
        command.requires_authentication = true;
        command.invalidates_session = true;
        return command.build();
    }

} // namespace desfire::ev3::native::checked
