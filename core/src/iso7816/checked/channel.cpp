/**
 * @file channel.cpp
 * @brief Checked ISO command validation and raw-channel delegation.
 */
#include <desfire/ev3/iso7816/checked/channel.hpp>

namespace desfire::ev3::iso7816::checked {

    /** @copydoc Channel::capabilities */
    TransportCapabilities Channel::capabilities() const {
        return channel_->capabilities();
    }

    /** @copydoc Channel::generation */
    std::uint64_t Channel::generation() const noexcept {
        return channel_->generation();
    }

    /** @copydoc Channel::exchange */
    Result<Response> Channel::exchange(const Command& command, const ExchangeOptions& options,
                                       const Limits& limits) {
        if ((command.is_selection() || command.is_write() || command.instruction() == 0x82 ||
             command.instruction() == 0x88) &&
            command.data().empty()) {
            return invalid("ISO checked command no longer owns its required payload");
        }
        raw::Limits raw_limits{limits.max_response, limits.max_frames,
                               limits.correct_read_length && command.is_read()};
        auto response = channel_->exchange(command.apdu(), options, raw_limits);
        if (!response) {
            return response.error();
        }
        return Response{response.value().status, std::move(response.value().data)};
    }

} // namespace desfire::ev3::iso7816::checked
