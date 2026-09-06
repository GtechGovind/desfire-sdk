/**
 * @file command.cpp
 * @brief Checked ISO command construction and semantic classification.
 */
#include <desfire/ev3/iso7816/checked/command.hpp>
#include <desfire/ev3/iso7816/raw/codec.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace desfire::ev3::iso7816::checked {

    namespace {

        /** @brief Return true for supported SELECT response selectors. */
        bool valid_selection_response(SelectionResponse response) noexcept {
            return response == SelectionResponse::fci || response == SelectionResponse::none;
        }

        /** @brief Match authentication random width to its ISO algorithm identifier. */
        bool valid_algorithm_length(Algorithm algorithm, std::size_t challenge_length) noexcept {
            switch (algorithm) {
            case Algorithm::context:
                return challenge_length == 8 || challenge_length == 16;
            case Algorithm::tdes2:
                return challenge_length == 8;
            case Algorithm::tdes3:
            case Algorithm::aes128:
                return challenge_length == 16;
            }
            return false;
        }

    } // namespace

    /** @copydoc BinaryAddress::current_file */
    Result<BinaryAddress> BinaryAddress::current_file(std::uint32_t offset) {
        if (offset > 0x7FFF) {
            return invalid("ISO current-file offset exceeds fifteen bits");
        }
        return BinaryAddress(static_cast<Byte>(offset >> 8U), static_cast<Byte>(offset));
    }

    /** @copydoc BinaryAddress::short_file */
    Result<BinaryAddress> BinaryAddress::short_file(std::uint32_t identifier,
                                                    std::uint32_t offset) {
        if (identifier > 31 || offset > 255) {
            return invalid("ISO short-file identifier or byte offset exceeds its field");
        }
        return BinaryAddress(static_cast<Byte>(0x80U | identifier), static_cast<Byte>(offset));
    }

    /** @copydoc KeyReference::application */
    Result<KeyReference> KeyReference::application(std::uint32_t number) {
        if (number > 13) {
            return invalid("ISO application key number must be zero through thirteen");
        }
        return KeyReference(static_cast<Byte>(0x80U | number));
    }

    Command::Command(Byte instruction, Byte p1, Byte p2, Bytes data,
                     std::optional<std::uint32_t> expected, LengthEncoding encoding)
        : apdu_{0x00, instruction, p1, p2, std::move(data), expected, encoding} {}

    /** @copydoc Command::make */
    Result<Command> Command::make(Byte instruction, Byte p1, Byte p2, ByteView data,
                                  std::optional<std::uint32_t> expected, LengthEncoding encoding) {
        Command command(instruction, p1, p2, Bytes(data.begin(), data.end()), expected, encoding);
        auto encoded = raw::encode(command.apdu());
        if (!encoded) {
            return encoded.error();
        }
        return command;
    }

    /** @copydoc Command::select_file */
    Result<Command> Command::select_file(std::uint32_t identifier, FileSelection selection,
                                         SelectionResponse response, LengthEncoding encoding) {
        if (identifier > 65535 || !valid_selection_response(response) ||
            (selection != FileSelection::by_identifier && selection != FileSelection::child_df &&
             selection != FileSelection::elementary_file)) {
            return invalid("ISO file selection has an invalid identifier or selector");
        }
        const std::array<Byte, 2> data{static_cast<Byte>(identifier >> 8U),
                                       static_cast<Byte>(identifier)};
        const std::optional<std::uint32_t> expected =
            response == SelectionResponse::fci
                ? std::optional<std::uint32_t>(encoding == LengthEncoding::extended ? 65536 : 256)
                : std::nullopt;
        return make(0xA4, static_cast<Byte>(selection), static_cast<Byte>(response), data, expected,
                    encoding);
    }

    /** @copydoc Command::select_df_name */
    Result<Command> Command::select_df_name(ByteView name, SelectionResponse response,
                                            LengthEncoding encoding) {
        if (name.empty() || name.size() > 16 || !valid_selection_response(response)) {
            return invalid("ISO DF name must contain one through sixteen bytes");
        }
        const std::optional<std::uint32_t> expected =
            response == SelectionResponse::fci
                ? std::optional<std::uint32_t>(encoding == LengthEncoding::extended ? 65536 : 256)
                : std::nullopt;
        return make(0xA4, 0x04, static_cast<Byte>(response), name, expected, encoding);
    }

    /** @copydoc Command::read_binary */
    Result<Command> Command::read_binary(BinaryAddress address, std::uint32_t expected,
                                         LengthEncoding encoding) {
        return make(0xB0, address.p1(), address.p2(), {}, expected, encoding);
    }

    /** @copydoc Command::update_binary */
    Result<Command> Command::update_binary(BinaryAddress address, ByteView data,
                                           LengthEncoding encoding) {
        if (data.empty()) {
            return invalid("ISO UPDATE BINARY requires nonempty data");
        }
        return make(0xD6, address.p1(), address.p2(), data, std::nullopt, encoding);
    }

    /** @copydoc Command::read_records */
    Result<Command> Command::read_records(std::uint32_t record, std::uint32_t short_identifier,
                                          RecordSelection selection, std::uint32_t expected,
                                          LengthEncoding encoding) {
        if (record > 255 || short_identifier > 31 ||
            (selection != RecordSelection::one && selection != RecordSelection::from_record)) {
            return invalid("ISO record selection exceeds its field or uses an invalid mode");
        }
        return make(0xB2, static_cast<Byte>(record),
                    static_cast<Byte>((short_identifier << 3U) | static_cast<Byte>(selection)), {},
                    expected, encoding);
    }

    /** @copydoc Command::append_record */
    Result<Command> Command::append_record(std::uint32_t short_identifier, ByteView data,
                                           LengthEncoding encoding) {
        if (short_identifier > 31 || data.empty()) {
            return invalid("ISO APPEND RECORD requires a five-bit identifier and nonempty data");
        }
        return make(0xE2, 0x00, static_cast<Byte>(short_identifier << 3U), data, std::nullopt,
                    encoding);
    }

    /** @copydoc Command::update_record */
    Result<Command> Command::update_record(UpdateRecordInstruction instruction,
                                           std::uint32_t record, std::uint32_t short_identifier,
                                           std::uint32_t reference_control, ByteView data) {
        if ((instruction != UpdateRecordInstruction::update_record_dc &&
             instruction != UpdateRecordInstruction::update_record_dd) ||
            record > 255 || short_identifier > 31 || reference_control > 7 || data.empty() ||
            data.size() > 255) {
            return invalid("ISO UPDATE RECORD has an invalid instruction, selector, or length");
        }
        const Byte p2 = static_cast<Byte>((short_identifier << 3U) | reference_control);
        return make(static_cast<Byte>(instruction), static_cast<Byte>(record), p2, data,
                    std::nullopt, LengthEncoding::short_apdu);
    }

    /** @copydoc Command::get_challenge */
    Result<Command> Command::get_challenge(std::uint32_t expected, LengthEncoding encoding) {
        if (expected != 8 && expected != 16) {
            return invalid("ISO GET CHALLENGE requires eight or sixteen bytes");
        }
        return make(0x84, 0x00, 0x00, {}, expected, encoding);
    }

    /** @copydoc Command::external_authenticate */
    Result<Command> Command::external_authenticate(Algorithm algorithm, KeyReference key,
                                                   ByteView cryptogram, LengthEncoding encoding) {
        if (cryptogram.size() % 2 != 0 ||
            !valid_algorithm_length(algorithm, cryptogram.size() / 2)) {
            return invalid(
                "ISO external authentication cryptogram length does not match its algorithm");
        }
        return make(0x82, static_cast<Byte>(algorithm), key.value(), cryptogram, std::nullopt,
                    encoding);
    }

    /** @copydoc Command::internal_authenticate */
    Result<Command> Command::internal_authenticate(Algorithm algorithm, KeyReference key,
                                                   ByteView challenge, LengthEncoding encoding) {
        if (!valid_algorithm_length(algorithm, challenge.size())) {
            return invalid(
                "ISO internal authentication challenge length does not match its algorithm");
        }
        return make(0x88, static_cast<Byte>(algorithm), key.value(), challenge,
                    static_cast<std::uint32_t>(challenge.size() * 2), encoding);
    }

    /** @copydoc Command::is_read */
    bool Command::is_read() const noexcept {
        return apdu_.ins == 0xB0 || apdu_.ins == 0xB2;
    }

    /** @copydoc Command::is_write */
    bool Command::is_write() const noexcept {
        return apdu_.ins == 0xD6 || apdu_.ins == 0xDC || apdu_.ins == 0xDD || apdu_.ins == 0xE2;
    }

    /** @copydoc Command::is_selection */
    bool Command::is_selection() const noexcept {
        return apdu_.ins == 0xA4;
    }

    /** @copydoc Command::resets_authentication */
    bool Command::resets_authentication() const noexcept {
        return (is_selection() && apdu_.p1 != 0x02) || apdu_.ins == 0x84 || apdu_.ins == 0x82 ||
               apdu_.ins == 0x88;
    }

} // namespace desfire::ev3::iso7816::checked
