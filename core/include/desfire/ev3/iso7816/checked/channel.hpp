/**
 * @file channel.hpp
 * @brief Semantic ISO command execution over an exclusively owned raw channel.
 */
#pragma once

#include "command.hpp"
#include "response.hpp"
#include <desfire/ev3/iso7816/raw/channel.hpp>

namespace desfire::ev3::iso7816::checked {

    /**
     * @brief Checked command facade borrowing one stable, exclusively owning raw channel.
     *
     * The raw channel must outlive this facade and any security session bound to it. Its internal
     * operation mutex serializes all checked and raw exchanges sharing that transport.
     */
    class Channel final {
    public:

        /**
         * @brief Bind semantic command handling to one stable raw channel.
         * @param channel Raw channel that outlives this object and its bound sessions.
         */
        explicit Channel(raw::Channel& channel) noexcept : channel_(&channel) {}

        /** @brief Prevent ambiguous rebinding of a security-session channel identity. */
        Channel(const Channel&) = delete;
        /** @brief Prevent ambiguous rebinding of a security-session channel identity. */
        Channel& operator=(const Channel&) = delete;
        /** @brief Keep the address stable for security sessions. */
        Channel(Channel&&) = delete;
        /** @brief Keep the address stable for security sessions. */
        Channel& operator=(Channel&&) = delete;

        /**
         * @brief Execute one checked command with bounded continuation and safe read correction.
         * @param command Immutable command previously accepted by a checked builder.
         * @param options Total timeout and cancellation controls for every physical frame.
         * @param limits Aggregate response and frame limits.
         * @return Checked response retaining warning/error status, or failure evidence.
         * @warning Mutations are never automatically repeated after uncertain delivery.
         */
        Result<Response> exchange(const Command& command, const ExchangeOptions& options = {},
                                  const Limits& limits = {});

        /** @brief Return immutable transport capabilities for preflight checks. */
        [[nodiscard]] TransportCapabilities capabilities() const;

        /** @brief Return the underlying card generation used to bind session state. */
        [[nodiscard]] std::uint64_t generation() const noexcept;

        /**
         * @brief Return whether this facade refers to the same raw channel as another facade.
         * @param other Checked channel to compare by raw-channel identity.
         * @return True when both facades refer to the same raw channel; false otherwise.
         */
        [[nodiscard]] bool same_channel(const Channel& other) const noexcept {
            return channel_ == other.channel_;
        }

    private:

        raw::Channel* channel_; ///< Channel identity to which this state is bound.
    };

} // namespace desfire::ev3::iso7816::checked
