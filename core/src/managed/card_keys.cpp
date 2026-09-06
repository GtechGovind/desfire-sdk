/**
 * @file card_keys.cpp
 * @brief Managed AES key settings, replacement, and key-set operations.
 */
#include <desfire/ev3/managed/card.hpp>

#include "model_names.hpp"

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Execute one successfully built key command.
         * @param card Managed card.
         * @param command Checked command or preflight error.
         * @param options Complete operation controls.
         * @return Status-free response or preserved failure evidence.
         */
        Result<Bytes> run(Card& card, Result<native::checked::Command> command,
                          const ExchangeOptions& options) {
            if (!command) {
                return command.error();
            }

            return card.execute(command.value(), options);
        }

        /**
         * @brief Execute one key mutation and discard its checked empty response.
         * @param card Managed card.
         * @param command Checked command or preflight error.
         * @param options Complete operation controls.
         * @return Success or preserved failure evidence.
         */
        Result<void> run_void(Card& card, Result<native::checked::Command> command,
                              const ExchangeOptions& options) {
            auto result = run(card, std::move(command), options);
            if (!result) {
                return result.error();
            }

            return {};
        }

    } // namespace

    /** @brief Read and parse current key settings. */
    Result<model::KeySettings> Card::key_settings(const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_key_settings(), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_key_settings(result.value());
    }

    /** @brief Change current application key settings through Full communication. */
    Result<void> Card::change_key_settings(Byte settings, const ExchangeOptions& options) {
        return run_void(*this, native::checked::change_key_settings(settings), options);
    }

    /** @brief Read exactly one key version byte. */
    Result<Byte> Card::key_version(model::KeyNumber key, std::optional<Byte> key_set,
                                   const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_key_version(key, key_set), options);
        if (!result) {
            return result.error();
        }
        if (result.value().size() != 1) {
            return Error{ErrorCode::malformed_response,
                         "GetKeyVersion response must contain exactly one byte", Outcome::unknown};
        }

        return result.value().front();
    }

    /** @brief Read the bounded key-set version byte sequence. */
    Result<Bytes> Card::key_set_versions(const ExchangeOptions& options) {
        return run(*this, native::checked::get_key_set_versions(), options);
    }

    /** @brief Replace one AES key under the tracked authenticated-key context. */
    Result<void> Card::change_aes_key(model::KeyNumber key, ByteView new_key, Byte version,
                                      model::KeyNumber authenticated_key, ByteView old_key,
                                      std::optional<Byte> key_set, bool picc_master_key,
                                      const ExchangeOptions& options) {
        return run_void(*this,
                        native::checked::change_aes_key(key, new_key, version, authenticated_key,
                                                        old_key, key_set, picc_master_key),
                        options);
    }

    /** @brief Initialize one checked AES key set. */
    Result<void> Card::initialize_key_set(Byte key_set, const ExchangeOptions& options) {
        return run_void(*this, native::checked::initialize_key_set(key_set), options);
    }

    /** @brief Finalize one checked AES key set and version. */
    Result<void> Card::finalize_key_set(Byte key_set, Byte version,
                                        const ExchangeOptions& options) {
        return run_void(*this, native::checked::finalize_key_set(key_set, version), options);
    }

    /** @brief Activate one checked key set and clear authentication after verified success. */
    Result<void> Card::roll_key_set(Byte key_set, const ExchangeOptions& options) {
        return run_void(*this, native::checked::roll_key_set(key_set), options);
    }

} // namespace desfire::ev3::managed
