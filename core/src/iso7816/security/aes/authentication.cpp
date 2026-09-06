/**
 * @file authentication.cpp
 * @brief Verified ISO mutual AES authentication implementation.
 */
#include "detail/session_support.hpp"
#include <desfire/ev3/iso7816/raw/codec.hpp>
#include <desfire/ev3/iso7816/security/aes/authentication.hpp>
#include <desfire/ev3/iso7816/security/aes/session.hpp>

#include <algorithm>
#include <array>
#include <utility>

namespace desfire::ev3::iso7816::security::aes {

    /** @brief Implement `authenticate` to complete ISO AES mutual authentication and install
     * verified session state. */
    Result<std::unique_ptr<Session>> authenticate(checked::Channel& channel, CryptoProvider& crypto,
                                                  checked::KeyReference reference,
                                                  ByteView derived_key,
                                                  const ExchangeOptions& options,
                                                  raw::LengthEncoding encoding) {
        bool attempted_io = false;
        try {
            if (derived_key.size() != 16 || options.timeout.count() <= 0 ||
                !detail::valid_encoding(encoding)) {
                return invalid(
                    "ISO AES authentication requires a sixteen-byte key and valid controls");
            }
            if (channel.capabilities().framing != Framing::iso7816) {
                return Error{ErrorCode::unsupported,
                             "ISO AES authentication requires an APDU transport"};
            }
            // Generate both independent host challenges before changing card state.
            detail::Budget budget(channel, options);
            auto preflight = budget.next(false);
            if (!preflight) {
                return preflight.error();
            }
            auto random = crypto.random(32);
            if (!random) {
                return random.error();
            }
            SecureBuffer host_random(std::move(random.value()));
            if (host_random.size() != 32) {
                return Error{ErrorCode::crypto,
                             "ISO AES provider returned the wrong random byte count"};
            }
            const auto host_first = host_random.view().first(16);
            const auto host_second = host_random.view().last(16);
            auto get_challenge = checked::Command::get_challenge(16, encoding);
            auto internal = checked::Command::internal_authenticate(
                checked::Algorithm::aes128, reference, host_second, encoding);
            const std::array<Byte, 32> dummy{};
            auto external_probe = checked::Command::external_authenticate(
                checked::Algorithm::aes128, reference, dummy, encoding);
            for (const checked::Command* command :
                 {&get_challenge.value(), &internal.value(), &external_probe.value()}) {
                auto frame = raw::encode(command->apdu());
                if (frame.value().size() > channel.capabilities().max_transmit) {
                    return invalid("ISO authentication frame exceeds transport transmit capacity");
                }
            }
            auto remaining = budget.next(false);
            if (!remaining) {
                return remaining.error();
            }
            attempted_io = true;
            auto first =
                detail::require_success(channel.exchange(get_challenge.value(), remaining.value(),
                                                         checked::Limits{16, 4, false}),
                                        16, "ISO GET CHALLENGE");
            if (!first) {
                return first.error();
            }
            SecureBuffer challenge(std::move(first.value().data));
            SecureBuffer proof(32);
            std::copy(host_first.begin(), host_first.end(), proof.mutable_view().begin());
            std::copy(challenge.view().begin(), challenge.view().end(),
                      proof.mutable_view().begin() + 16);
            const std::array<Byte, 16> zero_iv{};
            auto encrypted = crypto.cbc(Cipher::aes128, derived_key, zero_iv, proof.view(), true);
            if (!encrypted) {
                return detail::after_send(encrypted.error());
            }
            SecureBuffer ciphertext(std::move(encrypted.value()));
            if (ciphertext.size() != 32) {
                return Error{ErrorCode::crypto, "ISO AES provider returned the wrong proof length",
                             Outcome::unknown};
            }
            auto external = checked::Command::external_authenticate(
                checked::Algorithm::aes128, reference, ciphertext.view(), encoding);
            remaining = budget.next(true);
            if (!remaining) {
                return remaining.error();
            }
            auto second =
                detail::require_success(channel.exchange(external.value(), remaining.value(),
                                                         checked::Limits{32, 4, false}),
                                        0, "ISO EXTERNAL AUTHENTICATE");
            if (!second) {
                return detail::after_send(second.error());
            }
            remaining = budget.next(true);
            if (!remaining) {
                return remaining.error();
            }
            auto third =
                detail::require_success(channel.exchange(internal.value(), remaining.value(),
                                                         checked::Limits{32, 4, false}),
                                        32, "ISO INTERNAL AUTHENTICATE");
            if (!third) {
                return detail::after_send(third.error());
            }
            auto decrypted = crypto.cbc(Cipher::aes128, derived_key, ciphertext.view().last(16),
                                        third.value().data, false);
            if (!decrypted) {
                return detail::after_send(decrypted.error());
            }
            SecureBuffer card_proof(std::move(decrypted.value()));
            if (card_proof.size() != 32) {
                return Error{ErrorCode::crypto,
                             "ISO AES provider returned the wrong card proof length",
                             Outcome::unknown};
            }
            if (!detail::equal_secret(host_second, card_proof.view().last(16))) {
                return Error{ErrorCode::authentication,
                             "ISO card proof does not match the host challenge", Outcome::unknown};
            }
            remaining = budget.next(true);
            if (!remaining) {
                return remaining.error();
            }
            SecureBuffer session_key(16);
            auto key_bytes = session_key.mutable_view();
            std::copy_n(host_first.begin(), 4, key_bytes.begin());
            std::copy_n(card_proof.view().begin(), 4, key_bytes.begin() + 4);
            std::copy_n(host_first.begin() + 12, 4, key_bytes.begin() + 8);
            std::copy_n(card_proof.view().begin() + 12, 4, key_bytes.begin() + 12);
            return std::unique_ptr<Session>(
                new Session(reference, std::move(session_key), channel, budget.generation()));
        } catch (...) {
            return Error{ErrorCode::internal, "ISO AES authentication dependency failed",
                         attempted_io ? Outcome::unknown : Outcome::not_sent};
        }
    }

} // namespace desfire::ev3::iso7816::security::aes
