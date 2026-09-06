/**
 * @file transaction_plan.hpp
 * @brief Owned preflight plan for a managed DESFire transaction.
 */
#pragma once

#include <desfire/ev3/native/checked/command.hpp>

#include <span>
#include <vector>

namespace desfire::ev3::managed {

    /**
     * @brief Own one through 128 checked backup, value, or record mutations for atomic execution.
     *
     * Adding an operation performs structural validation only and never accesses the card. The
     * managed executor later checks each target's live file type and communication mode before it
     * sends the first mutation. A plan is move-only because `Command` owns potentially sensitive
     * data in move-only storage.
     */
    class TransactionPlan final {
    public:

        /** @brief Create an empty plan that can receive checked operations through `add()`. */
        TransactionPlan() = default;

        /** @brief Erase all operation data through each command's RAII-owned storage. */
        ~TransactionPlan() = default;

        /**
         * @brief Transfer all planned commands.
         * @param other Plan whose operation ownership is consumed.
         */
        TransactionPlan(TransactionPlan&& other) noexcept = default;

        /**
         * @brief Erase current operations before adopting another plan.
         * @param other Plan whose operation ownership is consumed.
         * @return This plan.
         */
        TransactionPlan& operator=(TransactionPlan&& other) noexcept = default;

        /** @brief Plans cannot copy move-only command payloads. */
        TransactionPlan(const TransactionPlan&) = delete;

        /** @brief Plans cannot copy-assign move-only command payloads. */
        TransactionPlan& operator=(const TransactionPlan&) = delete;

        /**
         * @brief Append one checked transactional mutation without card I/O.
         * @param command Move-only checked backup-write, value, or record mutation.
         * @return Success, or invalid_argument when the command is moved-from, nontransactional,
         * malformed, or would exceed 128 operations.
         */
        Result<void> add(native::checked::Command command) {
            if (operations_.size() >= maximum_operations) {
                return invalid("Transaction plan cannot exceed 128 operations");
            }
            if (!is_transactional_mutation(command)) {
                return invalid("Transaction plan accepts only typed backup/value/record mutations");
            }

            operations_.push_back(std::move(command));
            return {};
        }

        /**
         * @brief Return the current number of planned mutations.
         * @return Count from zero through 128.
         */
        [[nodiscard]] std::size_t size() const noexcept {
            return operations_.size();
        }

        /**
         * @brief Report whether no mutation has been added.
         * @return True only for an empty plan, which cannot be executed.
         */
        [[nodiscard]] bool empty() const noexcept {
            return operations_.empty();
        }

    private:

        friend class Card;

        /** @brief Hard transaction-plan operation limit used before any card I/O. */
        static constexpr std::size_t maximum_operations = 128;

        /**
         * @brief Check structural properties that do not require live file settings.
         * @param command Borrowed checked command.
         * @return True only for a valid backup, value, or record mutation acknowledgement.
         */
        static bool is_transactional_mutation(const native::checked::Command& command) noexcept {
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

        /**
         * @brief Borrow immutable commands for one synchronous managed execution.
         * @return Span valid until this plan is changed or destroyed.
         */
        [[nodiscard]] std::span<const native::checked::Command> operations() const noexcept {
            return operations_;
        }

        std::vector<native::checked::Command>
            operations_; ///< Validated transaction operations in execution order.
    };

} // namespace desfire::ev3::managed
