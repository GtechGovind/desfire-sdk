/**
 * @file applications.cpp
 * @brief Checked native application-command construction and response decoding.
 */
#include "detail/command_support.hpp"
#include <desfire/ev3/native/checked/applications.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <set>

namespace desfire::ev3::native::checked {

    using namespace detail;

    /** @brief Implement `parse_application_ids` to decode unique application identifiers. */
    Result<std::vector<model::ApplicationId>> parse_application_ids(ByteView payload) {
        if (payload.size() % 3 != 0 || payload.size() > maximum_logical_response) {
            return malformed("EV3 application identifiers require complete three-byte fields");
        }
        std::vector<model::ApplicationId> applications;
        std::set<std::uint32_t> unique;
        applications.reserve(payload.size() / 3);
        for (std::size_t offset = 0; offset < payload.size(); offset += 3) {
            const std::uint32_t value = get_le(payload.subspan(offset, 3));
            if (value == 0 || !unique.insert(value).second) {
                return malformed("EV3 application list contains a PICC or duplicate identifier");
            }
            applications.push_back(model::ApplicationId::make(value).value());
        }
        return applications;
    }

    /** @brief Implement `parse_iso_file_ids` to decode unique ISO file identifiers. */
    Result<std::vector<std::uint16_t>> parse_iso_file_ids(ByteView payload) {
        if (payload.size() % 2 != 0 || payload.size() > 64) {
            return malformed("EV3 ISO file identifiers require up to 32 complete two-byte fields");
        }
        std::vector<std::uint16_t> identifiers;
        std::set<std::uint16_t> unique;
        identifiers.reserve(payload.size() / 2);
        for (std::size_t offset = 0; offset < payload.size(); offset += 2) {
            const auto value = static_cast<std::uint16_t>(get_le(payload.subspan(offset, 2)));
            if (!unique.insert(value).second) {
                return malformed("EV3 ISO file list contains duplicate identifiers");
            }
            identifiers.push_back(value);
        }
        return identifiers;
    }

    /** @brief Implement `parse_df_name_frame` to decode one bounded DF-name response record. */
    Result<DfName> parse_df_name_frame(ByteView payload) {
        if (payload.size() < 5 || payload.size() > 21) {
            return malformed("EV3 DF name record must occupy one 5-to-21-byte response frame");
        }
        const std::uint32_t identifier = get_le(payload.first(3));
        if (identifier == 0) {
            return malformed("EV3 DF name contains the PICC application identifier");
        }
        return DfName{model::ApplicationId::make(identifier).value(),
                      static_cast<std::uint16_t>(get_le(payload.subspan(3, 2))),
                      Bytes(payload.begin() + 5, payload.end())};
    }

    /** @brief Implement `parse_delegated_application_info` to decode an exact delegated-slot
     * response. */
    Result<DelegatedApplicationInfo> parse_delegated_application_info(ByteView payload) {
        if (payload.size() != 8) {
            return malformed("GetDelegatedInfo response must contain exactly eight bytes");
        }
        const auto application = model::ApplicationId::make(get_le(payload.subspan(5, 3)));
        if (!application) {
            return malformed("GetDelegatedInfo response contains an invalid application ID");
        }
        return DelegatedApplicationInfo{
            payload[0], static_cast<std::uint16_t>(get_le(payload.subspan(1, 2))),
            static_cast<std::uint16_t>(get_le(payload.subspan(3, 2))), application.value()};
    }

    /** @brief Implement `get_application_ids` to build bounded application-identifier retrieval. */
    Result<Command> get_application_ids() {
        return management(0x6A, {}, 0, maximum_logical_response).build();
    }

    /** @brief Implement `get_df_names` to build DF-name retrieval. */
    Result<Command> get_df_names() {
        return management(0x6D, {}, 0, maximum_logical_response).build();
    }

    /** @brief Implement `get_iso_file_ids` to build ISO file-identifier retrieval. */
    Result<Command> get_iso_file_ids() {
        return management(0x61, {}, 0, 64).build();
    }

    /** @brief Implement `create_application` to build AES application creation. */
    Result<Command> create_application(const model::ApplicationConfiguration& settings) {
        auto tail = application_tail(settings);
        if (!tail) {
            return tail.error();
        }
        Bytes header;
        put_le(header, settings.id.value(), 3);
        append(header, tail.value());
        return management(0xCA, std::move(header)).build();
    }

    /** @brief Implement the documented delegated-application command builder. */
    Result<Command>
    create_delegated_application(const model::DelegatedApplicationConfiguration& settings,
                                 ByteView encrypted_default_key, ByteView dam_mac) {
        if (encrypted_default_key.size() != 32 || dam_mac.size() != 8) {
            return invalid(
                "Delegated application creation requires 32-byte EncK and 8-byte DAM MAC");
        }
        auto tail = application_tail(settings.application);
        if (!tail) {
            return tail.error();
        }

        Bytes header;
        put_le(header, settings.application.id.value(), 3);
        put_le(header, settings.slot, 2);
        header.push_back(settings.slot_version);
        put_le(header, settings.quota_limit, 2);
        append(header, tail.value());

        SecureBuffer authorization(40);
        std::ranges::copy(encrypted_default_key, authorization.mutable_view().begin());
        std::ranges::copy(dam_mac, authorization.mutable_view().begin() + 32);

        detail::CommandBuilder command = management(0xC9, std::move(header));
        command.data = std::move(authorization);
        command.requires_authentication = true;
        command.requires_ev2_session = true;
        command.requires_picc_selection = true;
        command.requires_single_continuation_frame = true;
        command.current_authenticated_key = 0x10;
        command.request_mode = model::CommunicationMode::mac;
        command.response_mode = model::CommunicationMode::mac;
        command.first_frame_payload_size = command.header.size();
        return command.build();
    }

    /** @brief Implement `get_delegated_application_info` to build delegated-slot information
     * retrieval. */
    Result<Command> get_delegated_application_info(std::uint16_t slot) {
        Bytes header;
        put_le(header, slot, 2);
        auto command = management(0x69, std::move(header), 8, 8);
        command.requires_picc_selection = true;
        return command.build();
    }

    /** @brief Implement `delete_application` to build protected application deletion. */
    Result<Command> delete_application(model::ApplicationId id) {
        if (id.value() == 0) {
            return invalid("DeleteApplication cannot target the PICC identifier");
        }
        Bytes header;
        put_le(header, id.value(), 3);
        return management(0xDA, std::move(header)).build();
    }

    /** @brief Implement `delete_delegated_application` to build issuer-authorized delegated
     * application deletion. */
    Result<Command> delete_delegated_application(model::ApplicationId id, ByteView dam_mac) {
        if (id.value() == 0 || dam_mac.size() != 8) {
            return invalid("Delegated deletion requires a nonzero AID and eight-byte DAM MAC");
        }
        Bytes header;
        put_le(header, id.value(), 3);
        append(header, dam_mac);
        auto command = management(0xDA, std::move(header));
        command.requires_authentication = true;
        command.requires_picc_selection = true;
        command.allowed_authenticated_keys =
            (std::uint64_t{1} << 0x10U) | (std::uint64_t{1} << 0x18U);
        return command.build();
    }

} // namespace desfire::ev3::native::checked
