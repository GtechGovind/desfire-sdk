/**
 * @file card_files.cpp
 * @brief Managed DESFire EV3 file creation, settings, data, value, and record operations.
 */
#include <desfire/ev3/managed/card.hpp>

#include "model_names.hpp"

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Execute one successfully built file command.
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
         * @brief Execute one file mutation and discard its checked empty response.
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

    /** @brief List and validate unique ISO file identifiers. */
    Result<std::vector<std::uint16_t>> Card::iso_file_ids(const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_iso_file_ids(), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_iso_file_ids(result.value());
    }

    /** @brief Read and strictly parse one file's settings. */
    Result<model::FileSettings> Card::file_settings(model::FileNumber file,
                                                    const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_file_settings(file), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_file_settings(result.value());
    }

    /** @brief Read and parse one signed value-file balance. */
    Result<std::int32_t> Card::value(model::FileNumber file, model::CommunicationMode mode,
                                     const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_value(file, mode), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_value(result.value());
    }

    /** @brief Read bounded file bytes at a validated three-byte offset. */
    Result<Bytes> Card::read_data(model::FileNumber file, model::Offset offset,
                                  model::ByteCount length, model::CommunicationMode mode,
                                  const ExchangeOptions& options) {
        return run(*this, native::checked::read_data(file, offset, length, mode), options);
    }

    /** @brief Write one owned command copy of borrowed file data. */
    Result<void> Card::write_data(model::FileNumber file, model::Offset offset, ByteView data,
                                  model::CommunicationMode mode, const ExchangeOptions& options) {
        return run_void(*this, native::checked::write_data(file, offset, data, mode), options);
    }

    /** @brief Create one checked standard or backup data file. */
    Result<void> Card::create_data_file(const model::DataFileConfiguration& configuration,
                                        const ExchangeOptions& options) {
        return run_void(*this, native::checked::create_data_file(configuration), options);
    }

    /** @brief Create one checked value file. */
    Result<void> Card::create_value_file(const model::ValueFileConfiguration& configuration,
                                         const ExchangeOptions& options) {
        return run_void(*this, native::checked::create_value_file(configuration), options);
    }

    /** @brief Create one checked linear or cyclic record file. */
    Result<void> Card::create_record_file(const model::RecordFileConfiguration& configuration,
                                          const ExchangeOptions& options) {
        return run_void(*this, native::checked::create_record_file(configuration), options);
    }

    /** @brief Create one transaction-MAC file using caller-owned AES key material. */
    Result<void> Card::create_transaction_mac_file(model::FileNumber file,
                                                   model::AccessRights access, ByteView aes_key,
                                                   Byte key_version,
                                                   const ExchangeOptions& options) {
        return run_void(
            *this, native::checked::create_transaction_mac_file(file, access, aes_key, key_version),
            options);
    }

    /** @brief Permanently delete one checked file. */
    Result<void> Card::delete_file(model::FileNumber file, const ExchangeOptions& options) {
        return run_void(*this, native::checked::delete_file(file), options);
    }

    /** @brief Read and parse the exact file-counter response. */
    Result<native::checked::FileCounters> Card::file_counters(model::FileNumber file,
                                                              model::CommunicationMode mode,
                                                              const ExchangeOptions& options) {
        auto result = run(*this, native::checked::get_file_counters(file, mode), options);
        if (!result) {
            return result.error();
        }

        return native::checked::parse_file_counters(result.value());
    }

    /** @brief Change one file's checked communication and access settings. */
    Result<void> Card::change_file_settings(const model::FileSettingsChange& configuration,
                                            const ExchangeOptions& options) {
        return run_void(*this, native::checked::change_file_settings(configuration), options);
    }

    /** @brief Stage one checked debit. */
    Result<void> Card::debit(model::FileNumber file, std::uint32_t amount,
                             model::CommunicationMode mode, const ExchangeOptions& options) {
        return run_void(*this, native::checked::debit(file, amount, mode), options);
    }

    /** @brief Stage one checked credit. */
    Result<void> Card::credit(model::FileNumber file, std::uint32_t amount,
                              model::CommunicationMode mode, const ExchangeOptions& options) {
        return run_void(*this, native::checked::credit(file, amount, mode), options);
    }

    /** @brief Stage one checked limited credit. */
    Result<void> Card::limited_credit(model::FileNumber file, std::uint32_t amount,
                                      model::CommunicationMode mode,
                                      const ExchangeOptions& options) {
        return run_void(*this, native::checked::limited_credit(file, amount, mode), options);
    }

    /** @brief Stage one checked restore transfer. */
    Result<void> Card::restore_transfer(model::FileNumber target, model::FileNumber source,
                                        model::CommunicationMode mode,
                                        const ExchangeOptions& options) {
        return run_void(*this, native::checked::restore_transfer(target, source, mode), options);
    }

    /** @brief Read bounded records from a checked index and count. */
    Result<Bytes> Card::read_records(model::FileNumber file, model::Offset first_record,
                                     model::ByteCount count, model::CommunicationMode mode,
                                     std::size_t maximum_response, const ExchangeOptions& options) {
        return run(*this,
                   native::checked::read_records(file, first_record, count, mode, maximum_response),
                   options);
    }

    /** @brief Stage one checked record append. */
    Result<void> Card::write_record(model::FileNumber file, model::Offset offset, ByteView data,
                                    model::CommunicationMode mode, const ExchangeOptions& options) {
        return run_void(*this, native::checked::write_record(file, offset, data, mode), options);
    }

    /** @brief Stage one checked existing-record update. */
    Result<void> Card::update_record(model::FileNumber file, model::Offset record,
                                     model::Offset offset, ByteView data,
                                     model::CommunicationMode mode,
                                     const ExchangeOptions& options) {
        return run_void(*this, native::checked::update_record(file, record, offset, data, mode),
                        options);
    }

    /** @brief Stage checked removal of all records in one file. */
    Result<void> Card::clear_record_file(model::FileNumber file, const ExchangeOptions& options) {
        return run_void(*this, native::checked::clear_record_file(file), options);
    }

} // namespace desfire::ev3::managed
