/**
 * @file command_support.hpp
 * @brief Private checked-native command assembly shared by domain translation units.
 */
#pragma once

#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/files.hpp>

#include <algorithm>
#include <limits>
#include <utility>

namespace desfire::ev3::native::checked::detail {

    /** @brief Mutable assembly state available only to checked command builders. */
    struct CommandBuilder {
        Byte opcode{};       ///< Native command opcode under construction.
        Bytes header{};      ///< Owned clear command header under construction.
        SecureBuffer data{}; ///< Owned sensitive command data under construction.
        model::CommunicationMode request_mode{
            model::CommunicationMode::mac}; ///< Required request communication mode.
        model::CommunicationMode response_mode{
            model::CommunicationMode::mac}; ///< Required response communication mode.
        std::size_t minimum_response{};     ///< Minimum accepted response length.
        std::size_t maximum_response{};     ///< Maximum accepted response length.
        bool requires_authentication{};     ///< Whether execution requires authentication.
        bool
            requires_ev2_session{}; ///< Whether execution specifically requires EV2 authentication.
        bool requires_picc_selection{}; ///< Whether the PICC must be selected before execution.
        bool requires_single_continuation_frame{}; ///< Whether remaining data must fit one
                                                   ///< continuation frame.
        bool invalidates_session{}; ///< Whether successful execution invalidates authentication.
        std::optional<Byte>
            current_authenticated_key{}; ///< Required authenticated key selector, when constrained.
        std::uint64_t allowed_authenticated_keys{}; ///< Bit set of authenticated key selectors
                                                    ///< permitted to execute.
        std::optional<std::size_t> first_frame_payload_size{}; ///< Required initial-frame payload
                                                               ///< length, when constrained.

        /**
         * @brief Seal validated fields into an immutable command.
         * @return Move-only command owning the assembled sensitive payload.
         */
        Command build() {
            return Command(std::move(*this));
        }
    };

} // namespace desfire::ev3::native::checked::detail

namespace desfire::ev3::native::checked::detail {

    using model::AccessRights;
    using model::ApplicationConfiguration;
    using model::CommunicationMode;
    using model::FileNumber;
    using model::Offset;

    inline constexpr std::uint32_t maximum_three_byte =
        0x00FFFFFFU; ///< Largest value representable by a DESFire three-byte field.
    inline constexpr std::size_t maximum_logical_response =
        16U * 1024U * 1024U; ///< Maximum supported aggregate logical response length.

    /**
     * @brief Report malformed card data without implying a safe retry.
     * @param message Redacted diagnostic description.
     * @return Malformed-response error with unknown delivery outcome.
     */
    inline Error malformed(std::string message) {
        return {ErrorCode::malformed_response, std::move(message), Outcome::unknown};
    }

    /**
     * @brief Check a native communication-mode enum.
     * @param mode Candidate enum value.
     * @return True for Plain, MAC, or Full.
     */
    inline bool valid_mode(CommunicationMode mode) {
        return mode == CommunicationMode::plain || mode == CommunicationMode::mac ||
               mode == CommunicationMode::full;
    }

    /**
     * @brief Check every access-right selector before four-bit encoding.
     * @param access Named access-right fields.
     * @return True when every selector is in range 0..15.
     */
    inline bool valid_access(const AccessRights& access) {
        return access.read_write <= 15 && access.change <= 15 && access.read <= 15 &&
               access.write <= 15;
    }

    /**
     * @brief Append access rights in native RW/CAR then R/W order.
     * @param output Destination byte vector.
     * @param access Validated access-right fields.
     */
    inline void append_access(Bytes& output, const AccessRights& access) {
        output.push_back(static_cast<Byte>((access.read_write << 4U) | access.change));
        output.push_back(static_cast<Byte>((access.read << 4U) | access.write));
    }

    /**
     * @brief Decode two length-checked access-right bytes.
     * @param input At least two bytes in native order.
     * @return Named access-right fields.
     * @pre input contains at least two bytes.
     */
    inline AccessRights read_access(ByteView input) {
        return {static_cast<Byte>(input[0] >> 4U), static_cast<Byte>(input[0] & 15U),
                static_cast<Byte>(input[1] >> 4U), static_cast<Byte>(input[1] & 15U)};
    }

    /**
     * @brief Start a management command that uses MAC when authenticated.
     * @param opcode Native instruction byte.
     * @param header Owned clear header bytes.
     * @param minimum Minimum status-free response length.
     * @param maximum Maximum status-free response length.
     * @return Mutable private builder.
     */
    inline detail::CommandBuilder management(Byte opcode, Bytes header = {},
                                             std::size_t minimum = 0, std::size_t maximum = 0) {
        detail::CommandBuilder command;
        command.opcode = opcode;
        command.header = std::move(header);
        command.minimum_response = minimum;
        command.maximum_response = maximum;
        return command;
    }

    /**
     * @brief Build a file command with caller-selected protection.
     * @param opcode Native instruction byte.
     * @param header Owned clear command header.
     * @param data Borrowed command data copied into secure storage.
     * @param mode Requested file communication mode.
     * @param reading True for reads whose Full request uses MAC.
     * @param minimum Minimum response bytes after protection removal.
     * @param maximum Maximum response bytes after protection removal.
     * @return Checked command or invalid_argument for an invalid mode.
     */
    inline Result<Command> file_command(Byte opcode, Bytes header, ByteView data,
                                        CommunicationMode mode, bool reading,
                                        std::size_t minimum = 0, std::size_t maximum = 0) {
        if (!valid_mode(mode)) {
            return invalid("Invalid EV3 communication mode");
        }
        detail::CommandBuilder command = management(opcode, std::move(header), minimum, maximum);
        command.data = SecureBuffer(data);
        command.requires_authentication = mode != CommunicationMode::plain;
        command.request_mode = mode;
        command.response_mode = mode;
        if (mode == CommunicationMode::full) {
            if (reading) {
                command.request_mode = CommunicationMode::mac;
            } else {
                command.response_mode = CommunicationMode::mac;
            }
        }
        return command.build();
    }

    /**
     * @brief Build an authenticated fully encrypted SetConfiguration command.
     * @param selector Documented configuration option byte.
     * @param data Owned sensitive configuration bytes.
     * @return Checked configuration command.
     */
    inline Command configuration(Byte selector, SecureBuffer data) {
        detail::CommandBuilder command = management(0x5C, {selector});
        command.request_mode = CommunicationMode::full;
        command.requires_authentication = true;
        command.data = std::move(data);
        return command.build();
    }

    /**
     * @brief Encode a file number and optional little-endian ISO identifier.
     * @param file Validated native file number.
     * @param iso_id Optional ISO file identifier.
     * @return Owned clear command header.
     */
    inline Bytes file_creation_prefix(FileNumber file, std::optional<std::uint16_t> iso_id) {
        Bytes header{static_cast<Byte>(file.value())};
        if (iso_id) {
            put_le(header, *iso_id, 2);
        }
        return header;
    }

    /**
     * @brief Encode file, offset, and length in native command order.
     * @param file Validated file number.
     * @param offset Validated three-byte offset.
     * @param length Validated three-byte length.
     * @return Owned clear command header.
     */
    inline Bytes range_header(FileNumber file, Offset offset, std::uint32_t length) {
        Bytes header{static_cast<Byte>(file.value())};
        put_le(header, offset.value(), 3);
        put_le(header, length, 3);
        return header;
    }

    /**
     * @brief Check that a byte range does not overflow a three-byte address space.
     * @param offset Validated starting offset.
     * @param length Candidate byte count.
     * @return True when both length and end position fit.
     */
    inline bool valid_range(Offset offset, std::size_t length) {
        return length <= maximum_three_byte && length <= maximum_three_byte - offset.value();
    }

    /**
     * @brief Validate AES application settings and encode fields after the AID.
     * @param settings Application metadata shared by ordinary and delegated creation.
     * @return Encoded fields or invalid_argument.
     */
    inline Result<Bytes> application_tail(const ApplicationConfiguration& settings) {
        if (settings.id.value() == 0 || settings.number_of_keys < 1 ||
            settings.number_of_keys > 14 || settings.df_name.size() > 16 ||
            (!settings.df_name.empty() && !settings.iso_id)) {
            return invalid("Invalid EV3 application ID, key count, or ISO directory name");
        }
        Byte third_settings = settings.key_settings3.value_or(0);
        if ((third_settings & 0xE8U) != 0 || ((third_settings & 1U) != 0 && !settings.key_sets)) {
            return invalid("Invalid EV3 third key settings or missing key-set configuration");
        }
        if (settings.key_sets) {
            const auto& sets = *settings.key_sets;
            if (sets.number_of_sets < 2 || sets.number_of_sets > 16 ||
                sets.maximum_key_size != 16) {
                return invalid("AES application key sets require 2..16 sets and 16-byte keys");
            }
            third_settings |= 1U;
        }

        Bytes fields{settings.key_settings};
        Byte second_settings = static_cast<Byte>(0x80U | settings.number_of_keys);
        if (settings.iso_file_identifiers) {
            second_settings |= 0x20U;
        }
        if (settings.key_settings3 || settings.key_sets) {
            second_settings |= 0x10U;
        }
        fields.push_back(second_settings);
        if (settings.key_settings3 || settings.key_sets) {
            fields.push_back(third_settings);
        }
        if (settings.key_sets) {
            const auto& sets = *settings.key_sets;
            append(fields, std::array<Byte, 4>{sets.active_version, sets.number_of_sets,
                                               sets.maximum_key_size, sets.settings});
        }
        if (settings.iso_id) {
            put_le(fields, *settings.iso_id, 2);
        }
        append(fields, settings.df_name);
        return fields;
    }

    /**
     * @brief Encode a nonnegative signed-32-bit value mutation.
     * @param opcode Credit, debit, or limited-credit opcode.
     * @param file Target value file.
     * @param amount Candidate nonnegative amount.
     * @param mode File communication mode.
     * @return Checked mutation or invalid_argument when amount exceeds INT32_MAX.
     */
    inline Result<Command> value_change(Byte opcode, FileNumber file, std::uint32_t amount,
                                        CommunicationMode mode) {
        if (amount > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
            return invalid("EV3 value operation amount exceeds signed 32-bit range");
        }
        Bytes amount_bytes;
        put_le(amount_bytes, amount, 4);
        return file_command(opcode, {static_cast<Byte>(file.value())}, amount_bytes, mode, false);
    }

    /**
     * @brief Copy a response after validating its exact length.
     * @tparam Length Required byte count.
     * @param payload Borrowed complete response payload.
     * @return Fixed array or malformed_response.
     */
    template <std::size_t Length>
    Result<std::array<Byte, Length>> fixed_response(ByteView payload) {
        if (payload.size() != Length) {
            return malformed("EV3 fixed response has an unexpected length");
        }
        std::array<Byte, Length> output{};
        std::copy(payload.begin(), payload.end(), output.begin());
        return output;
    }

} // namespace desfire::ev3::native::checked::detail
