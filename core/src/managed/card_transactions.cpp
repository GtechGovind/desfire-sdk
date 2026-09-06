/**
 * @file card_transactions.cpp
 * @brief Managed transaction planning, staging, commit, abort, and reader identification.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "model_names.hpp"
#include "operation_guard.hpp"

#include <array>
#include <chrono>

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Execute one successfully built transaction command.
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
         * @brief Execute one transaction control command and discard its checked empty response.
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

        /**
         * @brief Recheck that a borrowed command has transactional mutation structure.
         * @param command Borrowed checked command.
         * @return True for backup writes and value/record mutations with empty responses.
         */
        bool is_transactional_mutation(const native::checked::Command& command) noexcept {
            if (!command.valid()) {
                return false;
            }

            const bool is_value =
                command.opcode() == 0x0C || command.opcode() == 0xDC || command.opcode() == 0x1C;
            const bool is_record =
                command.opcode() == 0x3B || command.opcode() == 0xDB || command.opcode() == 0xEB;
            return (is_value || is_record || command.opcode() == 0x3D) &&
                   !command.header().empty() && command.header().front() <= 31 &&
                   command.minimum_response() == 0 && command.maximum_response() == 0 &&
                   !command.invalidates_session();
        }

    } // namespace

    /** @brief Commit staged mutations once and optionally return a transaction-MAC receipt. */
    Result<Bytes> Card::commit_transaction(bool return_mac, const ExchangeOptions& options) {
        return run(*this, native::checked::commit_transaction(return_mac), options);
    }

    /** @brief Abort staged mutations once without automatic retry. */
    Result<void> Card::abort_transaction(const ExchangeOptions& options) {
        return run_void(*this, native::checked::abort_transaction(), options);
    }

    /** @brief Commit one reader identifier and return its verified response bytes. */
    Result<Bytes> Card::commit_reader_id(ByteView reader_id, const ExchangeOptions& options) {
        return run(*this, native::checked::commit_reader_id(reader_id), options);
    }

    /** @brief Implement `execute_transaction` to execute a prevalidated transaction plan. */
    Result<Bytes> Card::execute_transaction(const TransactionPlan& plan, bool return_mac,
                                            const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Transaction cannot reenter an active Card operation"};
        }

        return execute_transaction_locked(plan.operations(), return_mac, options);
    }

    /** @brief Implement `execute_transaction_locked` to execute a transaction plan under one
     * managed admission. */
    Result<Bytes>
    Card::execute_transaction_locked(std::span<const native::checked::Command> operations,
                                     bool return_mac, const ExchangeOptions& options) {
        try {
            if (!impl_->usable || impl_->iso_session) {
                return Error{ErrorCode::session_invalid,
                             "Transaction requires usable native card state"};
            }
            if (operations.empty() || operations.size() > 128 || options.timeout.count() <= 0) {
                return invalid("Transaction requires 1..128 mutations and a positive timeout");
            }

            const auto deadline = std::chrono::steady_clock::now() + options.timeout;
            /** @brief Derive controls for the next subcommand from one transaction deadline. */
            const auto remaining_options = [&]() -> Result<ExchangeOptions> {
                const auto now = std::chrono::steady_clock::now();
                if (options.stop.stop_requested()) {
                    return Error{ErrorCode::cancelled, "Transaction cancelled"};
                }
                if (now >= deadline) {
                    return Error{ErrorCode::timeout, "Transaction deadline expired"};
                }

                auto remaining = options;
                remaining.timeout = std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
                return remaining;
            };

            for (const auto& command : operations) {
                if (!is_transactional_mutation(command)) {
                    return invalid("Transaction accepts only typed backup/value/record mutations");
                }
            }

            std::array<std::optional<model::FileSettings>, 32> settings;
            for (const auto& command : operations) {
                const Byte file_number = command.header().front();
                if (!settings[file_number]) {
                    auto budget = remaining_options();
                    if (!budget) {
                        return budget.error();
                    }
                    auto query = native::checked::get_file_settings(
                        model::FileNumber::make(file_number).value());
                    if (!query) {
                        return query.error();
                    }
                    auto raw_settings = execute_locked(query.value(), budget.value());
                    if (!raw_settings) {
                        return raw_settings.error();
                    }
                    auto parsed = native::checked::parse_file_settings(raw_settings.value());
                    if (!parsed) {
                        invalidate_locked();
                        return parsed.error();
                    }
                    settings[file_number] = std::move(parsed.value());
                }

                const auto& file = *settings[file_number];
                const bool expected_type =
                    (command.opcode() == 0x3D && file.type == model::FileType::backup_data) ||
                    ((command.opcode() == 0x0C || command.opcode() == 0xDC ||
                      command.opcode() == 0x1C) &&
                     file.type == model::FileType::value) ||
                    ((command.opcode() == 0x3B || command.opcode() == 0xDB ||
                      command.opcode() == 0xEB) &&
                     (file.type == model::FileType::linear_record ||
                      file.type == model::FileType::cyclic_record));
                if (!expected_type) {
                    return invalid("Mutation targets a nontransactional file type");
                }
                if (command.opcode() != 0xEB && command.request_mode() != file.communication) {
                    return invalid(
                        "Transaction communication mode differs from verified file settings");
                }
            }

            bool staged = false;
            for (const auto& command : operations) {
                auto budget = remaining_options();
                Result<Bytes> result = budget ? execute_locked(command, budget.value())
                                              : Result<Bytes>(budget.error());
                if (!result) {
                    auto error = result.error();
                    if (staged || error.outcome == Outcome::unknown) {
                        error.outcome = Outcome::unknown;
                        invalidate_locked();
                    }
                    return error;
                }
                staged = true;
            }

            auto budget = remaining_options();
            if (!budget) {
                auto error = budget.error();
                error.outcome = Outcome::unknown;
                invalidate_locked();
                return error;
            }
            auto commit = native::checked::commit_transaction(return_mac);
            if (!commit) {
                invalidate_locked();
                return commit.error();
            }
            auto receipt = execute_locked(commit.value(), budget.value());
            if (!receipt) {
                auto error = receipt.error();
                error.outcome = Outcome::unknown;
                invalidate_locked();
                return error;
            }

            return receipt;
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "Transaction operation failed", Outcome::unknown};
        }
    }

} // namespace desfire::ev3::managed
