/**
 * @file session_support.hpp
 * @brief Private ISO AES authentication, proof, deadline, and retained-CMAC helpers.
 */
#pragma once

#include <desfire/ev3/iso7816/checked/channel.hpp>
#include <desfire/foundation/crypto_provider.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>

namespace desfire::ev3::iso7816::security::aes::detail {

    /** @brief ISO status word confirming command success. */
    inline constexpr std::uint16_t success_status = 0x9000;
    /** @brief Largest checked literal Le accepted by the APDU codec. */
    inline constexpr std::uint32_t maximum_expected_data = 65536;

    /**
     * @brief Report whether an authentication APDU length policy is supported.
     * @param encoding Candidate policy.
     * @return True for automatic, short, or extended encoding.
     */
    inline bool valid_encoding(raw::LengthEncoding encoding) noexcept {
        return encoding == raw::LengthEncoding::automatic ||
               encoding == raw::LengthEncoding::short_apdu ||
               encoding == raw::LengthEncoding::extended;
    }

    /** @brief One elapsed-time budget and generation shared by all authentication steps. */
    class Budget final {
    public:

        /**
         * @brief Snapshot a checked channel generation and start the authentication clock.
         * @param channel Channel used for every proof step.
         * @param options Total authentication controls.
         */
        Budget(checked::Channel& channel, const ExchangeOptions& options)
            : channel_(channel), options_(options), generation_(channel.generation()) {}

        /**
         * @brief Produce controls with the remaining deadline for the next proof step.
         * @param sent True after any earlier frame reached the card.
         * @return Remaining controls or conservative cancellation/generation/timeout evidence.
         */
        Result<ExchangeOptions> next(bool sent) const {
            const auto outcome = sent ? Outcome::unknown : Outcome::not_sent;
            if (channel_.generation() != generation_) {
                return Error{ErrorCode::card_removed,
                             "Card state changed during ISO AES authentication", outcome};
            }
            if (options_.stop.stop_requested()) {
                return Error{ErrorCode::cancelled, "ISO AES authentication cancelled", outcome};
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started_);
            if (options_.timeout.count() <= 0 || elapsed >= options_.timeout) {
                return Error{ErrorCode::timeout, "ISO AES authentication deadline expired",
                             outcome};
            }
            ExchangeOptions remaining = options_;
            remaining.timeout -= elapsed;
            return remaining;
        }

        /** @brief Return the generation captured before the first proof frame. */
        [[nodiscard]] std::uint64_t generation() const noexcept {
            return generation_;
        }

    private:

        checked::Channel& channel_; ///< Channel identity to which this state is bound.
        ExchangeOptions options_;   ///< Timeout and cancellation controls shared by the operation.
        std::uint64_t generation_;  ///< Card generation captured when this state was created.
        std::chrono::steady_clock::time_point started_{
            std::chrono::steady_clock::now()}; ///< Whether the logical operation has begun card
                                               ///< I/O.
    };

    /**
     * @brief Change a not-sent dependency error to unknown after earlier card delivery.
     * @param error Error to refine.
     * @return Error with conservative delivery evidence.
     */
    inline Error after_send(Error error) {
        if (error.outcome == Outcome::not_sent) {
            error.outcome = Outcome::unknown;
        }
        return error;
    }

    /**
     * @brief Construct malformed-response evidence with an optional ISO status word.
     * @param message Non-sensitive structural failure description.
     * @param status Observed status or zero when unavailable.
     * @return Malformed-response error with unknown delivery outcome.
     */
    inline Error malformed(std::string message, std::uint16_t status = 0) {
        return Error{ErrorCode::malformed_response, std::move(message), Outcome::unknown, status};
    }

    /**
     * @brief Compare fixed-width authentication values without value-dependent early exit.
     * @param left First secret view.
     * @param right Second secret view.
     * @return True when sizes and every byte match.
     */
    inline bool equal_secret(ByteView left, ByteView right) noexcept {
        if (left.size() != right.size()) {
            return false;
        }
        volatile unsigned difference = 0;
        for (std::size_t index = 0; index < left.size(); ++index) {
            difference = difference | static_cast<unsigned>(left[index] ^ right[index]);
        }
        return difference == 0;
    }

    /**
     * @brief Double one AES-CMAC subkey in big-endian polynomial representation.
     * @param input Exact sixteen-byte subkey.
     * @return Doubled subkey.
     */
    inline std::array<Byte, 16> double_subkey(ByteView input) {
        std::array<Byte, 16> result{};
        Byte carry = 0;
        for (std::size_t index = result.size(); index-- > 0;) {
            result[index] = static_cast<Byte>((static_cast<unsigned>(input[index]) << 1U) | carry);
            carry = static_cast<Byte>(input[index] >> 7U);
        }
        if (carry != 0) {
            result.back() ^= 0x87;
        }
        return result;
    }

    /**
     * @brief Calculate AES CMAC while retaining a caller-supplied initial chaining value.
     * @param crypto AES no-padding CBC provider.
     * @param key Exact sixteen-byte AES key.
     * @param iv Exact sixteen-byte retained chaining value.
     * @param input Borrowed message bytes.
     * @return Exact sixteen-byte CMAC in erased-on-release storage.
     */
    inline Result<SecureBuffer> retained_cmac(CryptoProvider& crypto, ByteView key, ByteView iv,
                                              ByteView input) {
        const std::array<Byte, 16> zero{};
        auto base = crypto.cbc(Cipher::aes128, key, zero, zero, true);
        if (!base) {
            return base.error();
        }
        SecureBuffer base_key(std::move(base.value()));
        if (base_key.size() != 16) {
            return Error{ErrorCode::crypto, "ISO AES provider returned invalid CMAC subkey size"};
        }
        auto subkey = double_subkey(base_key.view());
        const bool complete = !input.empty() && input.size() % 16 == 0;
        if (!complete) {
            auto second = double_subkey(subkey);
            wipe(subkey);
            subkey = second;
            wipe(second);
        }
        const std::size_t padded_size = (input.size() / 16 + (complete ? 0U : 1U)) * 16;
        SecureBuffer blocks(padded_size);
        auto bytes = blocks.mutable_view();
        std::copy(input.begin(), input.end(), bytes.begin());
        if (!complete) {
            bytes[input.size()] = 0x80;
        }
        for (std::size_t index = 0; index < 16; ++index) {
            bytes[padded_size - 16 + index] ^= subkey[index];
        }
        wipe(subkey);
        auto encrypted = crypto.cbc(Cipher::aes128, key, iv, blocks.view(), true);
        if (!encrypted) {
            return encrypted.error();
        }
        SecureBuffer ciphertext(std::move(encrypted.value()));
        if (ciphertext.size() != padded_size) {
            return Error{ErrorCode::crypto, "ISO AES provider returned invalid CMAC block size"};
        }
        return SecureBuffer(ciphertext.view().last(16));
    }

    /**
     * @brief Require ISO success and an exact authentication payload length.
     * @param response Completed checked exchange result.
     * @param exact_length Required response-data length.
     * @param operation Redacted operation name for error evidence.
     * @return Valid response or card-rejection/malformed-response evidence.
     */
    inline Result<checked::Response> require_success(Result<checked::Response> response,
                                                     std::size_t exact_length,
                                                     std::string_view operation) {
        if (!response) {
            return response.error();
        }
        if (!response.value().success()) {
            return Error{ErrorCode::card_rejected, std::string(operation) + " rejected",
                         Outcome::rejected, response.value().status};
        }
        if (response.value().data.size() != exact_length) {
            return malformed(std::string(operation) + " returned an unexpected length",
                             success_status);
        }
        return response;
    }

} // namespace desfire::ev3::iso7816::security::aes::detail
