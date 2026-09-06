/**
 * @file card_management.hpp
 * @brief Checked DESFire EV3 discovery, UID, originality, and configuration commands.
 */
#pragma once

#include "command.hpp"
#include <desfire/ev3/model/settings.hpp>
#include <desfire/ev3/model/version.hpp>

#include <array>
#include <optional>

namespace desfire::ev3::native::checked {

    /** @brief Select the documented GetCardUID command-data variant. */
    enum class CardUidRequest { omit_option, without_nuid, with_nuid };

    /** @brief Validated UID plus an optional four-byte NUID suffix. */
    struct CardUid final {
        Bytes uid{};                               ///< Seven-byte UID or documented UID response.
        std::optional<std::array<Byte, 4>> nuid{}; ///< Optional four-byte NUID suffix.
    };

    /**
     * @brief Decode a UID response whose option form is not known by the caller.
     * @param payload Complete status-free UID response.
     * @return Parsed UID without an inferred NUID option, or malformed_response.
     */
    Result<CardUid> parse_card_uid(ByteView payload);

    /**
     * @brief Decode the exact response layout for a selected UID option variant.
     * @param payload Complete status-free UID response.
     * @param request Option variant used to issue GetCardUID.
     * @return Parsed UID/NUID fields or malformed_response.
     */
    Result<CardUid> parse_card_uid(ByteView payload, CardUidRequest request);

    /**
     * @brief Copy exactly 56 originality-signature bytes.
     * @param payload Exact status-free originality signature response.
     * @return Fixed-width signature or malformed_response.
     */
    Result<std::array<Byte, 56>> parse_originality_signature(ByteView payload);

    /** @brief Build fixed-length GetVersion. */
    Result<Command> get_version();

    /** @brief Build FreeMem with an exact three-byte response. */
    Result<Command> free_memory();

    /** @brief Build authenticated GetCardUID without an option byte. */
    Result<Command> get_card_uid();

    /** @brief Build authenticated GetCardUID with an explicit option variant. */
    Result<Command> get_card_uid(CardUidRequest request);

    /** @brief Build originality-signature read with an exact 56-byte response. */
    Result<Command> read_originality_signature();

    /** @brief Build authenticated PICC formatting and session invalidation. */
    Result<Command> format_picc();

    /** @brief Build SetConfiguration option 0 from named PICC flags. */
    Result<Command> set_picc_configuration(const model::PiccConfiguration& configuration);

    /** @brief Build SetConfiguration option 5 from an exact capability record. */
    Result<Command>
    set_capability_configuration(const model::CapabilityConfiguration& configuration);

    /** @brief Build SetConfiguration option 1 for an AES-128 default application key. */
    Result<Command> set_default_aes_key(ByteView aes_key, Byte key_version);

    /** @brief Build SetConfiguration option 2 for a complete 2..20-byte ATS. */
    Result<Command> set_ats(ByteView ats);

    /** @brief Build SetConfiguration option 4 from a two-byte little-endian ATQA. */
    Result<Command> set_atqa(std::uint16_t atqa);

} // namespace desfire::ev3::native::checked
