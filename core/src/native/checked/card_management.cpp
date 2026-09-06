/**
 * @file card_management.cpp
 * @brief Checked native card-management command construction and response decoding.
 */
#include "detail/command_support.hpp"
#include <desfire/ev3/native/checked/card_management.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <set>

namespace desfire::ev3::native::checked {

    using namespace detail;

    /** @brief Implement `parse_card_uid` to decode a validated card UID response. */
    Result<CardUid> parse_card_uid(ByteView payload, CardUidRequest request) {
        ByteView uid_payload = payload;
        std::optional<std::array<Byte, 4>> nuid;
        switch (request) {
        case CardUidRequest::omit_option:
        case CardUidRequest::without_nuid:
            break;
        case CardUidRequest::with_nuid:
            if (payload.size() < 4) {
                return malformed("EV3 UID response omits the requested four-byte NUID");
            }
            uid_payload = payload.first(payload.size() - 4);
            nuid.emplace();
            std::copy(payload.end() - 4, payload.end(), nuid->begin());
            break;
        default:
            return invalid("Invalid GetCardUID request variant");
        }

        if (uid_payload.size() == 7) {
            return CardUid{Bytes(uid_payload.begin(), uid_payload.end()), nuid};
        }
        if ((uid_payload.size() != 6 && uid_payload.size() != 12) || uid_payload[0] != 0 ||
            uid_payload[1] != uid_payload.size() - 2) {
            return malformed("EV3 UID response has an invalid length or format prefix");
        }
        return CardUid{Bytes(uid_payload.begin() + 2, uid_payload.end()), nuid};
    }

    /** @brief Implement `parse_card_uid` to decode a validated card UID response. */
    Result<CardUid> parse_card_uid(ByteView payload) {
        return parse_card_uid(payload, CardUidRequest::omit_option);
    }

    /** @brief Implement `parse_originality_signature` to decode the exact originality-signature
     * response. */
    Result<std::array<Byte, 56>> parse_originality_signature(ByteView payload) {
        return fixed_response<56>(payload);
    }

    /** @brief Implement `get_version` to build bounded version retrieval. */
    Result<Command> get_version() {
        return management(0x60, {}, 28, 28).build();
    }

    /** @brief Implement `free_memory` to build free-memory retrieval. */
    Result<Command> free_memory() {
        return management(0x6E, {}, 3, 3).build();
    }

    /** @brief Implement `get_card_uid` to build a validated card-UID request. */
    Result<Command> get_card_uid(CardUidRequest request) {
        Bytes header;
        std::size_t minimum_response = 6;
        std::size_t maximum_response = 12;
        switch (request) {
        case CardUidRequest::omit_option:
            break;
        case CardUidRequest::without_nuid:
            header.push_back(0x00);
            break;
        case CardUidRequest::with_nuid:
            header.push_back(0x01);
            minimum_response += 4;
            maximum_response += 4;
            break;
        default:
            return invalid("Invalid GetCardUID request variant");
        }
        return file_command(0x51, std::move(header), {}, model::CommunicationMode::full, true,
                            minimum_response, maximum_response);
    }

    /** @brief Implement `get_card_uid` to build a validated card-UID request. */
    Result<Command> get_card_uid() {
        return get_card_uid(CardUidRequest::omit_option);
    }

    /** @brief Implement `read_originality_signature` to build exact originality-signature
     * retrieval. */
    Result<Command> read_originality_signature() {
        detail::CommandBuilder command = management(0x3C, {0x00}, 56, 56);
        command.response_mode = model::CommunicationMode::full;
        return command.build();
    }

    /** @brief Implement `format_picc` to build authenticated PICC formatting. */
    Result<Command> format_picc() {
        detail::CommandBuilder command = management(0xFC);
        command.requires_authentication = true;
        return command.build();
    }

    /** @brief Implement `set_picc_configuration` to build the documented PICC configuration
     * mutation. */
    Result<Command> set_picc_configuration(const model::PiccConfiguration& settings) {
        Byte flags = 0;
        const std::array<bool, 7> bits{settings.disable_format,
                                       settings.random_identifier,
                                       settings.proximity_check_mandatory,
                                       settings.virtual_card_authentication_mandatory,
                                       settings.error_code_binding,
                                       settings.random_identifier_configuration,
                                       settings.four_byte_nuid_configuration};
        for (std::size_t index = 0; index < bits.size(); ++index) {
            if (bits[index]) {
                flags |= static_cast<Byte>(1U << index);
            }
        }
        return configuration(0x00, SecureBuffer(Bytes{flags}));
    }

    /** @brief Implement `set_capability_configuration` to build the exact capability-configuration
     * mutation. */
    Result<Command> set_capability_configuration(const model::CapabilityConfiguration& settings) {
        return configuration(0x05, SecureBuffer(settings.data));
    }

    /** @brief Implement `set_default_aes_key` to build default AES-key replacement. */
    Result<Command> set_default_aes_key(ByteView aes_key, Byte key_version) {
        if (aes_key.size() != 16) {
            return invalid("Default AES key requires sixteen bytes");
        }
        SecureBuffer data(25);
        std::copy(aes_key.begin(), aes_key.end(), data.mutable_view().begin());
        data.mutable_view()[24] = key_version;
        return configuration(0x01, std::move(data));
    }

    /** @brief Implement `set_ats` to build ATS replacement with validated length. */
    Result<Command> set_ats(ByteView ats) {
        if (ats.size() < 2 || ats.size() > 20 || ats[0] != ats.size()) {
            return invalid("ATS must include a matching length byte and contain 2..20 bytes");
        }
        return configuration(0x02, SecureBuffer(ats));
    }

    /** @brief Implement `set_atqa` to build ATQA replacement in card byte order. */
    Result<Command> set_atqa(std::uint16_t atqa) {
        Bytes data;
        put_le(data, atqa, 2);
        return configuration(0x0C, SecureBuffer(std::move(data)));
    }

} // namespace desfire::ev3::native::checked
