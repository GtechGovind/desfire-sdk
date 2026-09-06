/**
 * @file command.hpp
 * @brief Immutable checked DESFire EV3 native command contract.
 */
#pragma once

#include <desfire/ev3/model/communication.hpp>
#include <desfire/foundation/secure_buffer.hpp>

#include <cstdint>
#include <optional>

namespace desfire::ev3::native::checked {

    namespace detail {
        struct CommandBuilder;
    }

    /**
     * @brief One validated move-only native command with fixed protection and response policy.
     *
     * Checked builders own every request byte. Card applies framing, authentication, secure
     * messaging, continuation, and complete response bounds.
     */
    class Command final {
    public:

        /**
         * @brief Transfer validated command ownership.
         * @param other Command whose sensitive storage is transferred.
         */
        Command(Command&& other) noexcept;

        /**
         * @brief Erase current sensitive storage before adopting a replacement.
         * @param other Command whose validated state is transferred.
         * @return This command after ownership transfer.
         */
        Command& operator=(Command&& other) noexcept;

        /** @brief Prevent copying sensitive command storage. */
        Command(const Command&) = delete;

        /** @brief Prevent copy assignment of sensitive command storage. */
        Command& operator=(const Command&) = delete;

        /** @brief Release the command and erase sensitive data through SecureBuffer. */
        ~Command() = default;

        /** @brief Return whether this object still owns a command after moves. */
        [[nodiscard]] bool valid() const noexcept {
            return valid_;
        }

        /** @brief Return the checked native opcode. */
        [[nodiscard]] Byte opcode() const noexcept {
            return opcode_;
        }

        /** @brief Borrow clear header bytes for this command's lifetime. */
        [[nodiscard]] const Bytes& header() const noexcept {
            return header_;
        }

        /** @brief Borrow sensitive command data for this command's lifetime. */
        [[nodiscard]] ByteView data() const noexcept {
            return data_.view();
        }

        /** @brief Return the request communication mode fixed by the builder. */
        [[nodiscard]] model::CommunicationMode request_mode() const noexcept {
            return request_mode_;
        }

        /** @brief Return the response communication mode fixed by the builder. */
        [[nodiscard]] model::CommunicationMode response_mode() const noexcept {
            return response_mode_;
        }

        /** @brief Return the minimum authenticated and decrypted response length. */
        [[nodiscard]] std::size_t minimum_response() const noexcept {
            return minimum_response_;
        }

        /** @brief Return the maximum authenticated and decrypted response length. */
        [[nodiscard]] std::size_t maximum_response() const noexcept {
            return maximum_response_;
        }

        /** @brief Report whether execution requires an authenticated native session. */
        [[nodiscard]] bool requires_authentication() const noexcept {
            return requires_authentication_;
        }

        /** @brief Report whether successful execution invalidates native authentication. */
        [[nodiscard]] bool invalidates_session() const noexcept {
            return invalidates_session_;
        }

        /** @brief Return a required current authentication selector when present. */
        [[nodiscard]] std::optional<Byte> current_authenticated_key() const noexcept {
            return current_authenticated_key_;
        }

        /** @brief Report whether execution is restricted to selected authenticated keys. */
        [[nodiscard]] bool restricts_authenticated_key() const noexcept {
            return allowed_authenticated_keys_ != 0;
        }

        /**
         * @brief Test a selector against the checked command's authentication-key set.
         * @param key Candidate authenticated key number.
         * @return True when unrestricted or explicitly allowed.
         */
        [[nodiscard]] bool accepts_authenticated_key(Byte key) const noexcept {
            return allowed_authenticated_keys_ == 0 ||
                   (key < 64 && (allowed_authenticated_keys_ & (std::uint64_t{1} << key)) != 0);
        }

        /** @brief Report whether Standard AES secure messaging is forbidden. */
        [[nodiscard]] bool requires_ev2_session() const noexcept {
            return requires_ev2_session_;
        }

        /** @brief Report whether tracked PICC selection is required. */
        [[nodiscard]] bool requires_picc_selection() const noexcept {
            return requires_picc_selection_;
        }

        /** @brief Report whether remaining request data must fit one additional frame. */
        [[nodiscard]] bool requires_single_continuation_frame() const noexcept {
            return requires_single_continuation_frame_;
        }

        /**
         * @brief Return a protocol-required initial-frame payload length when present.
         * @return Required byte count, or no value when the first frame is unconstrained.
         */
        [[nodiscard]] std::optional<std::size_t> first_frame_payload_size() const noexcept {
            return first_frame_payload_size_;
        }

    private:

        friend struct detail::CommandBuilder;

        /**
         * @brief Seal a completely checked internal builder.
         * @param builder Validated fields whose ownership is transferred.
         */
        explicit Command(detail::CommandBuilder&& builder) noexcept;

        Byte opcode_{};       ///< Validated native command opcode.
        Bytes header_{};      ///< Owned clear command header.
        SecureBuffer data_{}; ///< Owned sensitive command payload.
        model::CommunicationMode request_mode_{
            model::CommunicationMode::mac}; ///< Required request communication mode.
        model::CommunicationMode response_mode_{
            model::CommunicationMode::mac}; ///< Required response communication mode.
        std::size_t minimum_response_{};    ///< Minimum accepted response length.
        std::size_t maximum_response_{};    ///< Maximum accepted response length.
        bool requires_authentication_{};    ///< Whether command execution requires authentication.
        bool requires_ev2_session_{};       ///< Whether command execution specifically requires EV2
                                            ///< authentication.
        bool requires_picc_selection_{};    ///< Whether the PICC must be selected before execution.
        bool requires_single_continuation_frame_{}; ///< Whether remaining request data must fit one
                                                    ///< continuation frame.
        bool invalidates_session_{}; ///< Whether successful execution invalidates authentication.
        std::optional<Byte> current_authenticated_key_{}; ///< Required authenticated key selector,
                                                          ///< when constrained.
        std::uint64_t allowed_authenticated_keys_{}; ///< Bit set of authenticated key selectors
                                                     ///< permitted to execute.
        std::optional<std::size_t> first_frame_payload_size_{}; ///< Required initial-frame payload
                                                                ///< length, when constrained.
        bool valid_{}; ///< Whether this object still owns valid protocol state.
    };

} // namespace desfire::ev3::native::checked
