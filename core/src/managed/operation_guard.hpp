/**
 * @file operation_guard.hpp
 * @brief Recursive-entry-aware managed Card operation serialization.
 */
#pragma once

#include <mutex>

namespace desfire::ev3::managed {

    /**
     * @brief Serialize threads while rejecting nested Card entry from a transport callback.
     *
     * A recursive mutex lets the same thread inspect the active flag instead of deadlocking. It
     * never permits a nested protocol operation to proceed or interleave continuation frames.
     */
    class OperationGuard final {
    public:

        /**
         * @brief Acquire the Card lock and mark the outer operation active.
         * @param mutex Card-wide recursive mutex.
         * @param active Card-wide activity flag protected by `mutex`.
         */
        OperationGuard(std::recursive_mutex& mutex, bool& active)
            : lock_(mutex), active_(active), entered_(!active) {
            if (entered_) {
                active_ = true;
            }
        }

        /** @brief Clear activity only for the outer operation before unlocking. */
        ~OperationGuard() {
            if (entered_) {
                active_ = false;
            }
        }

        /** @brief Operation guards cannot duplicate lock ownership. */
        OperationGuard(const OperationGuard&) = delete;

        /** @brief Operation guards cannot copy-assign lock ownership. */
        OperationGuard& operator=(const OperationGuard&) = delete;

        /** @brief Operation guards remain tied to their active flag and cannot move. */
        OperationGuard(OperationGuard&&) = delete;

        /** @brief Operation guards remain tied to their active flag and cannot move-assign. */
        OperationGuard& operator=(OperationGuard&&) = delete;

        /**
         * @brief Report whether this guard owns the outer managed operation.
         * @return False only for nested same-thread entry.
         */
        explicit operator bool() const noexcept {
            return entered_;
        }

    private:

        std::unique_lock<std::recursive_mutex>
            lock_;     ///< Lock that serializes managed card operation admission.
        bool& active_; ///< Shared reentrancy flag protected by the admission lock.
        bool entered_; ///< Whether this guard acquired operation admission.
    };

} // namespace desfire::ev3::managed
