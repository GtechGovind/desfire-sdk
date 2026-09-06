/**
 * @file session.cpp
 * @brief Counter-based DESFire EV2 secure-messaging construction available on EV3.
 */
#include <desfire/ev3/security/ev2/session.hpp>

#include <algorithm>
#include <array>
#include <limits>

namespace desfire::ev3::security::ev2 {

    namespace {

        /** @brief AES block size used by the implemented EV2 secure-messaging methods. */
        constexpr std::size_t aes_block_size = 16;
        /** @brief Number of alternate full-CMAC bytes transmitted by EV2. */
        constexpr std::size_t transmitted_mac_size = 8;

        /**
         * @brief Adopt provider output into sensitive storage and require the exact output size.
         * @param result Primitive output to consume.
         * @param expected Required output length.
         * @return Secret storage, or the provider failure.
         */
        Result<SecureBuffer> secret_output(Result<Bytes> result, std::size_t expected) {
            if (!result) {
                return result.error();
            }
            SecureBuffer output(std::move(result.value()));
            if (output.size() != expected) {
                return Error{ErrorCode::crypto,
                             "EV2 secure-message primitive returned an invalid length"};
            }
            return output;
        }

        /**
         * @brief Extract the EV2 transmitted bytes from a complete AES-CMAC.
         * @param full_mac Complete sixteen-byte CMAC.
         * @return Bytes at positions 1, 3, ..., 15, or a provider-length error.
         */
        Result<std::array<Byte, transmitted_mac_size>> truncate_mac(ByteView full_mac) {
            if (full_mac.size() != aes_block_size) {
                return Error{ErrorCode::crypto, "EV2 CMAC has an invalid length"};
            }
            std::array<Byte, transmitted_mac_size> output{};
            for (std::size_t index = 0; index < output.size(); ++index) {
                output[index] = full_mac[(index * 2) + 1];
            }
            return output;
        }

        /**
         * @brief Append a command counter in the native little-endian byte order.
         * @param output Destination receiving two bytes.
         * @param counter Current EV2 command counter.
         */
        void append_counter(Bytes& output, std::uint16_t counter) {
            output.push_back(static_cast<Byte>(counter));
            output.push_back(static_cast<Byte>(counter >> 8U));
        }

        /**
         * @brief Add ISO/IEC 9797-1 method-2 padding to sensitive command data.
         * @param data Plain command data.
         * @return Whole-block `data || 0x80 || zeroes` storage.
         */
        Result<SecureBuffer> pad_method_2(ByteView data) {
            if (data.size() > std::numeric_limits<std::size_t>::max() - aes_block_size) {
                return invalid("EV2 Full command data is too large to pad");
            }
            const auto unrounded_size = data.size() + 1;
            const auto size =
                ((unrounded_size + aes_block_size - 1) / aes_block_size) * aes_block_size;
            SecureBuffer padded(size);
            std::ranges::copy(data, padded.mutable_view().begin());
            padded.mutable_view()[data.size()] = 0x80;
            return padded;
        }

    } // namespace

    /** @brief Implement `Session` to own verified EV2 keys, metadata, and command-counter state. */
    Session::Session(std::shared_ptr<CryptoProvider> crypto, AuthenticationMaterial material,
                     std::uint16_t counter)
        : crypto_(std::move(crypto)), encryption_key_(std::move(material.encryption_key)),
          mac_key_(std::move(material.mac_key)), authentication_(material.information),
          counter_(counter) {}

    /** @brief Implement `create` to validate authentication material and create session state. */
    Result<std::unique_ptr<Session>> Session::create(std::shared_ptr<CryptoProvider> crypto,
                                                     AuthenticationMaterial material,
                                                     std::uint16_t counter) {
        if (!crypto || material.encryption_key.size() != aes_block_size ||
            material.mac_key.size() != aes_block_size) {
            return invalid("EV2 secure session requires AES provider and two 16-byte keys");
        }
        return std::unique_ptr<Session>(
            new Session(std::move(crypto), std::move(material), counter));
    }

    /** @copydoc Session::prepare_plain */
    Result<Bytes> Session::prepare_plain(Byte command, ByteView header, ByteView data) {
        (void)command;
        if (phase_ != Phase::ready) {
            return Error{ErrorCode::session_invalid, "EV2 secure session is not ready"};
        }
        if (counter_ == std::numeric_limits<std::uint16_t>::max()) {
            invalidate();
            return Error{ErrorCode::counter_exhausted,
                         "EV2 command counter exhausted; authenticate before more I/O"};
        }
        if (header.size() > std::numeric_limits<std::size_t>::max() - data.size()) {
            return invalid("EV2 Plain command data is too large");
        }
        try {
            Bytes output;
            output.reserve(header.size() + data.size());
            append(output, header);
            append(output, data);
            ++counter_;
            phase_ = Phase::awaiting_plain_response;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "EV2 Plain command preparation failed"};
        }
    }

    /** @copydoc Session::accept_plain_response */
    Result<Bytes> Session::accept_plain_response(const native::raw::Response& response) {
        if (phase_ != Phase::awaiting_plain_response) {
            return Error{ErrorCode::session_invalid,
                         "EV2 secure session is not awaiting a Plain response"};
        }
        if (response.status != 0x00) {
            invalidate();
            if (response.status == 0xAF) {
                return Error{ErrorCode::malformed_response, "EV2 Plain response is not terminal",
                             Outcome::unknown, response.status};
            }
            return Error{ErrorCode::card_rejected, "Card rejected EV2 Plain command",
                         Outcome::rejected, response.status};
        }
        try {
            Bytes output(response.data);
            phase_ = Phase::ready;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "EV2 Plain response allocation failed",
                         Outcome::unknown};
        }
    }

    /** @brief Implement `prepare_mac` to protect a native command with EV2 command MACing. */
    Result<Bytes> Session::prepare_mac(Byte command, ByteView header, ByteView data) {
        if (phase_ != Phase::ready) {
            return Error{ErrorCode::session_invalid, "EV2 secure session is not ready"};
        }
        if (counter_ == std::numeric_limits<std::uint16_t>::max()) {
            invalidate();
            return Error{ErrorCode::counter_exhausted,
                         "EV2 command counter exhausted; authenticate before more I/O"};
        }
        constexpr auto maximum = std::numeric_limits<std::size_t>::max();
        if (data.size() > maximum - transmitted_mac_size ||
            header.size() > maximum - transmitted_mac_size - data.size()) {
            return invalid("EV2 secure-message MAC input is too large");
        }

        try {
            Bytes mac_input;
            mac_input.reserve(7U + header.size() + data.size());
            mac_input.push_back(command);
            append_counter(mac_input, counter_);
            append(mac_input, authentication_.transaction_identifier);
            append(mac_input, header);
            append(mac_input, data);
            auto full_mac = secret_output(crypto_->cmac(Cipher::aes128, mac_key_.view(), mac_input),
                                          aes_block_size);
            if (!full_mac) {
                invalidate();
                return full_mac.error();
            }
            auto truncated = truncate_mac(full_mac.value().view());
            if (!truncated) {
                invalidate();
                return truncated.error();
            }

            Bytes output;
            output.reserve(header.size() + data.size() + transmitted_mac_size);
            append(output, header);
            append(output, data);
            append(output, truncated.value());
            ++counter_;
            phase_ = Phase::awaiting_response;
            return output;
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "EV2 command MAC construction failed"};
        }
    }

    /** @brief Implement `prepare_full` to encrypt and authenticate a native command with EV2 full
     * protection. */
    Result<Bytes> Session::prepare_full(Byte command, ByteView clear_header, ByteView clear_data) {
        if (phase_ != Phase::ready) {
            return Error{ErrorCode::session_invalid, "EV2 secure session is not ready"};
        }
        if (counter_ == std::numeric_limits<std::uint16_t>::max()) {
            invalidate();
            return Error{ErrorCode::counter_exhausted,
                         "EV2 command counter exhausted; authenticate before more I/O"};
        }
        // Commands with only a clear header (for example ReadData) have no
        // encrypted command field, even when their response uses Full mode.
        if (clear_data.empty()) {
            return prepare_mac(command, clear_header, {});
        }
        try {
            auto padded = pad_method_2(clear_data);
            if (!padded) {
                return padded.error();
            }
            std::array<Byte, aes_block_size> iv_input{};
            iv_input[0] = 0xA5;
            iv_input[1] = 0x5A;
            std::ranges::copy(authentication_.transaction_identifier, iv_input.begin() + 2);
            iv_input[6] = static_cast<Byte>(counter_);
            iv_input[7] = static_cast<Byte>(counter_ >> 8U);
            const std::array<Byte, aes_block_size> zero_iv{};
            auto iv = secret_output(
                crypto_->cbc(Cipher::aes128, encryption_key_.view(), zero_iv, iv_input, true),
                aes_block_size);
            if (!iv) {
                invalidate();
                return iv.error();
            }
            auto ciphertext =
                secret_output(crypto_->cbc(Cipher::aes128, encryption_key_.view(),
                                           iv.value().view(), padded.value().view(), true),
                              padded.value().size());
            if (!ciphertext) {
                invalidate();
                return ciphertext.error();
            }
            return prepare_mac(command, clear_header, ciphertext.value().view());
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "EV2 Full command protection failed"};
        }
    }

    /** @brief Implement `verify_response` to verify an EV2 response MAC and advance the command
     * counter. */
    Result<Bytes> Session::verify_response(const native::raw::Response& response) {
        if (phase_ != Phase::awaiting_response) {
            return Error{ErrorCode::session_invalid,
                         "EV2 secure session is not awaiting a response"};
        }
        if (response.status != 0x00) {
            invalidate();
            if (response.status == 0xAF) {
                return Error{ErrorCode::malformed_response,
                             "EV2 protected response is not terminal", Outcome::unknown,
                             response.status};
            }
            return Error{ErrorCode::card_rejected, "Card rejected EV2 protected command",
                         Outcome::rejected, response.status};
        }
        if (response.data.size() < transmitted_mac_size) {
            invalidate();
            return Error{ErrorCode::integrity, "EV2 protected response has no complete MAC",
                         Outcome::unknown};
        }
        try {
            const auto data_size = response.data.size() - transmitted_mac_size;
            const auto data = ByteView{response.data}.first(data_size);
            const auto received_mac = ByteView{response.data}.subspan(data_size);
            Bytes mac_input;
            mac_input.reserve(7U + data.size());
            mac_input.push_back(response.status);
            append_counter(mac_input, counter_);
            append(mac_input, authentication_.transaction_identifier);
            append(mac_input, data);
            auto full_mac = secret_output(crypto_->cmac(Cipher::aes128, mac_key_.view(), mac_input),
                                          aes_block_size);
            if (!full_mac) {
                invalidate();
                auto error = full_mac.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            auto expected_mac = truncate_mac(full_mac.value().view());
            if (!expected_mac) {
                invalidate();
                return expected_mac.error();
            }
            if (!constant_time_equal(received_mac, expected_mac.value())) {
                invalidate();
                return Error{ErrorCode::integrity, "EV2 protected response MAC verification failed",
                             Outcome::unknown};
            }
            phase_ = Phase::ready;
            return Bytes(data.begin(), data.end());
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "EV2 response MAC verification failed",
                         Outcome::unknown};
        }
    }

    /** @brief Implement `verify_and_decrypt_full_response` to verify and decrypt an EV2
     * full-protection response. */
    Result<Bytes>
    Session::verify_and_decrypt_full_response(const native::raw::Response& response,
                                              std::optional<std::size_t> expected_size) {
        auto ciphertext = verify_response(response);
        if (!ciphertext) {
            return ciphertext.error();
        }
        if (ciphertext.value().empty() && (!expected_size || *expected_size == 0)) {
            return Bytes{};
        }
        if (ciphertext.value().empty() || ciphertext.value().size() % aes_block_size != 0) {
            invalidate();
            return Error{ErrorCode::integrity,
                         "EV2 Full response ciphertext must contain whole AES blocks",
                         Outcome::unknown};
        }
        try {
            std::array<Byte, aes_block_size> iv_input{};
            iv_input[0] = 0x5A;
            iv_input[1] = 0xA5;
            std::ranges::copy(authentication_.transaction_identifier, iv_input.begin() + 2);
            iv_input[6] = static_cast<Byte>(counter_);
            iv_input[7] = static_cast<Byte>(counter_ >> 8U);
            const std::array<Byte, aes_block_size> zero_iv{};
            auto iv = secret_output(
                crypto_->cbc(Cipher::aes128, encryption_key_.view(), zero_iv, iv_input, true),
                aes_block_size);
            if (!iv) {
                invalidate();
                auto error = iv.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            auto plaintext =
                secret_output(crypto_->cbc(Cipher::aes128, encryption_key_.view(),
                                           iv.value().view(), ciphertext.value(), false),
                              ciphertext.value().size());
            if (!plaintext) {
                invalidate();
                auto error = plaintext.error();
                error.outcome = Outcome::unknown;
                return error;
            }
            const auto padded = plaintext.value().view();
            auto marker = padded.size();
            while (marker > 0 && padded[marker - 1] == 0x00) {
                --marker;
            }
            if (marker == 0 || padded[marker - 1] != 0x80 ||
                padded.size() - (marker - 1) > aes_block_size) {
                invalidate();
                return Error{ErrorCode::integrity, "EV2 Full response has invalid method-2 padding",
                             Outcome::unknown};
            }
            if (expected_size && marker - 1 != *expected_size) {
                invalidate();
                return Error{ErrorCode::integrity,
                             "EV2 Full response plaintext length differs from the request",
                             Outcome::unknown};
            }
            const auto clear = padded.first(marker - 1);
            return Bytes(clear.begin(), clear.end());
        } catch (...) {
            invalidate();
            return Error{ErrorCode::internal, "EV2 Full response decryption failed",
                         Outcome::unknown};
        }
    }

    /**
     * @brief Return the counter assigned to the next protected command.
     * @return Current EV2 command counter.
     */
    std::uint16_t Session::command_counter() const noexcept {
        return counter_;
    }

    /**
     * @brief Return verified transaction metadata without exposing either session key.
     * @return Immutable First-authentication metadata.
     */
    const model::AuthenticationInfo& Session::authentication() const noexcept {
        return authentication_;
    }

    /** @copydoc Session::invalidate */
    void Session::invalidate() noexcept {
        wipe(encryption_key_.mutable_view());
        wipe(mac_key_.mutable_view());
        counter_ = 0;
        phase_ = Phase::invalid;
    }

} // namespace desfire::ev3::security::ev2
