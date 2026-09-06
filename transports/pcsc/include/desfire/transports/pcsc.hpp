/**
 * @file pcsc.hpp
 * @brief Desktop PC/SC discovery for contactless cards and contact SAM connections.
 */
#pragma once

#include <desfire/foundation/transport.hpp>

#include <memory>

namespace desfire::transports {

    /**
     * @brief Open the platform PC/SC service for explicit reader enumeration and selection.
     *
     * Uses the system framework on macOS, WinSCard on Windows, and pcsc-lite on Linux.
     * The protocol core does not depend on any of those libraries. The resulting
     * connections exchange ISO APDUs; native RF framing is not advertised.
     *
     * @return An owned reader provider, or a transport error if the service is unavailable.
     * @note Portable SCardTransmit does not provide an interruptible per-call timeout.
     * The adapter checks budgets before/after I/O, but a driver may block longer.
     * Cancellation and RF timing capabilities are therefore not advertised.
     */
    Result<std::shared_ptr<ReaderProvider>> pcsc_provider();

} // namespace desfire::transports
