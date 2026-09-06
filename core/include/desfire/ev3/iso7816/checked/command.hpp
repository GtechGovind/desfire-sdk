/**
 * @file command.hpp
 * @brief Checked ISO/IEC 7816-4 command models for DESFire EV3.
 */
#pragma once

#include <desfire/ev3/iso7816/raw/apdu.hpp>

#include <optional>

namespace desfire::ev3::iso7816::checked {

    /** @brief Raw APDU length policy accepted by checked command builders. */
    using LengthEncoding = raw::LengthEncoding;

    /** @brief Supported ISO file-selection scopes. */
    enum class FileSelection : Byte {
        by_identifier = 0x00,
        child_df = 0x01,
        elementary_file = 0x02
    };

    /** @brief Request file-control information or selection status only. */
    enum class SelectionResponse : Byte { fci = 0x00, none = 0x0C };

    /** @brief Absolute record selection modes. */
    enum class RecordSelection : Byte { one = 0x04, from_record = 0x05 };

    /** @brief Documented ISO UPDATE RECORD instruction-byte alternatives. */
    enum class UpdateRecordInstruction : Byte {
        update_record_dc = 0xDC,
        update_record_dd = 0xDD,
        dc = update_record_dc,
        dd = update_record_dd
    };

    /** @brief ISO algorithm identifiers used by primitive authentication commands. */
    enum class Algorithm : Byte { context = 0x00, tdes2 = 0x02, tdes3 = 0x04, aes128 = 0x09 };

    /** @brief Validated P1/P2 address for READ BINARY and UPDATE BINARY. */
    class BinaryAddress final {
    public:

        /** @brief Address the current EF using a 15-bit byte offset. */
        static Result<BinaryAddress> current_file(std::uint32_t offset);

        /** @brief Address a five-bit short file identifier with an eight-bit offset. */
        static Result<BinaryAddress> short_file(std::uint32_t identifier, std::uint32_t offset);

        /** @brief Return the validated P1 byte. */
        [[nodiscard]] Byte p1() const noexcept {
            return p1_;
        }

        /** @brief Return the validated P2 byte. */
        [[nodiscard]] Byte p2() const noexcept {
            return p2_;
        }

    private:

        /** @brief Retain validated binary-address bytes. */
        BinaryAddress(Byte p1, Byte p2) : p1_(p1), p2_(p2) {}

        Byte p1_; ///< Encoded APDU P1 address byte.
        Byte p2_; ///< Encoded APDU P2 address byte.
    };

    /** @brief Validated ISO authentication key reference. */
    class KeyReference final {
    public:

        /** @brief Select PICC master key reference zero. */
        static KeyReference picc_master() noexcept {
            return KeyReference(0);
        }

        /** @brief Select an application key numbered zero through thirteen. */
        static Result<KeyReference> application(std::uint32_t number);

        /** @brief Return the complete ISO key-reference byte. */
        [[nodiscard]] Byte value() const noexcept {
            return value_;
        }

    private:

        /**
         * @brief Retain a validated ISO key-reference byte.
         * @param value Validated key-reference byte.
         */
        explicit KeyReference(Byte value) : value_(value) {}

        Byte value_; ///< Validated numeric value.
    };

    /**
     * @brief Immutable validated ISO command using CLA 00.
     *
     * Expected lengths are literal counts 1..65536. Primitive authentication commands accept
     * caller-prepared bytes and do not establish a trusted session.
     */
    class Command final {
    public:

        /** @brief Build SELECT FILE by a two-byte ISO identifier. */
        static Result<Command> select_file(std::uint32_t identifier,
                                           FileSelection selection = FileSelection::by_identifier,
                                           SelectionResponse response = SelectionResponse::fci,
                                           LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build SELECT FILE by a one-through-sixteen-byte DF name. */
        static Result<Command> select_df_name(ByteView name,
                                              SelectionResponse response = SelectionResponse::fci,
                                              LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build READ BINARY for one through 65,536 expected bytes. */
        static Result<Command> read_binary(BinaryAddress address, std::uint32_t expected,
                                           LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build UPDATE BINARY with one through 65,535 owned bytes. */
        static Result<Command> update_binary(BinaryAddress address, ByteView data,
                                             LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build READ RECORDS with a checked record selector and response bound. */
        static Result<Command> read_records(std::uint32_t record, std::uint32_t short_identifier,
                                            RecordSelection selection, std::uint32_t expected,
                                            LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build APPEND RECORD with a checked short file identifier. */
        static Result<Command> append_record(std::uint32_t short_identifier, ByteView data,
                                             LengthEncoding encoding = LengthEncoding::automatic);

        /**
         * @brief Build one documented short-form ISO UPDATE RECORD variant.
         * @param instruction Select the documented 0xDC or 0xDD instruction byte.
         * @param record Record number 0..255; zero denotes the current record.
         * @param short_identifier Five-bit short file identifier; zero uses the selected EF.
         * @param reference_control Three low P2 control bits defined for the instruction.
         * @param data One through 255 bytes copied into owned storage.
         * @return Checked short APDU command or invalid_argument before I/O.
         */
        static Result<Command> update_record(UpdateRecordInstruction instruction,
                                             std::uint32_t record, std::uint32_t short_identifier,
                                             std::uint32_t reference_control, ByteView data);

        /** @brief Build GET CHALLENGE for exactly eight or sixteen bytes. */
        static Result<Command> get_challenge(std::uint32_t expected = 16,
                                             LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build EXTERNAL AUTHENTICATE from a prepared cryptogram. */
        static Result<Command>
        external_authenticate(Algorithm algorithm, KeyReference key, ByteView cryptogram,
                              LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Build INTERNAL AUTHENTICATE from a plaintext host challenge. */
        static Result<Command>
        internal_authenticate(Algorithm algorithm, KeyReference key, ByteView challenge,
                              LengthEncoding encoding = LengthEncoding::automatic);

        /** @brief Return the ISO instruction byte. */
        [[nodiscard]] Byte instruction() const noexcept {
            return apdu_.ins;
        }

        /** @brief Return the checked P1 byte. */
        [[nodiscard]] Byte p1() const noexcept {
            return apdu_.p1;
        }

        /** @brief Return the checked P2 byte. */
        [[nodiscard]] Byte p2() const noexcept {
            return apdu_.p2;
        }

        /** @brief Borrow owned command data for this command's lifetime. */
        [[nodiscard]] ByteView data() const noexcept {
            return apdu_.data;
        }

        /** @brief Return the literal expected response length when present. */
        [[nodiscard]] std::optional<std::uint32_t> expected_length() const noexcept {
            return apdu_.le;
        }

        /** @brief Return the checked APDU length-representation policy. */
        [[nodiscard]] LengthEncoding encoding() const noexcept {
            return apdu_.encoding;
        }

        /** @brief Borrow the structurally valid raw APDU owned by this checked command. */
        [[nodiscard]] const raw::Apdu& apdu() const noexcept {
            return apdu_;
        }

        /** @brief Report whether a safe unauthenticated 6C length correction is possible. */
        [[nodiscard]] bool is_read() const noexcept;

        /** @brief Report whether this is an ISO data mutation. */
        [[nodiscard]] bool is_write() const noexcept;

        /** @brief Report whether this is an ISO file-selection command. */
        [[nodiscard]] bool is_selection() const noexcept;

        /** @brief Report whether selection changes the authentication context. */
        [[nodiscard]] bool resets_authentication() const noexcept;

    private:

        /** @brief Own validated ISO command fields. */
        Command(Byte instruction, Byte p1, Byte p2, Bytes data,
                std::optional<std::uint32_t> expected, LengthEncoding encoding);

        /** @brief Validate all fields before owning borrowed command data. */
        static Result<Command> make(Byte instruction, Byte p1, Byte p2, ByteView data,
                                    std::optional<std::uint32_t> expected, LengthEncoding encoding);

        raw::Apdu apdu_; ///< Validated APDU owned by this command.
    };

} // namespace desfire::ev3::iso7816::checked
