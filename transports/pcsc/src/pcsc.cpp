/**
 * @file pcsc.cpp
 * @brief System PC/SC resource ownership and APDU transport without command retries.
 */
#include <desfire/transports/pcsc.hpp>

#if defined(__APPLE__)
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#elif defined(_WIN32)
#include <winscard.h>
#else
#include <winscard.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace desfire::transports {

    namespace {

        /**
         * @brief Map a platform PC/SC status into stable transport error evidence.
         * @param status PC/SC status returned by one system call.
         * @param outcome Delivery evidence appropriate to the call that returned @p status.
         * @return A redacted SDK error without reader frame payloads.
         */
        Error pcsc_error(LONG status, Outcome outcome = Outcome::not_sent) {
            ErrorCode category = ErrorCode::transport;

            if (static_cast<std::uint32_t>(status) ==
                    static_cast<std::uint32_t>(SCARD_E_NO_SMARTCARD) ||
                static_cast<std::uint32_t>(status) ==
                    static_cast<std::uint32_t>(SCARD_W_REMOVED_CARD) ||
                static_cast<std::uint32_t>(status) ==
                    static_cast<std::uint32_t>(SCARD_W_RESET_CARD)) {
                category = ErrorCode::card_removed;
            } else if (static_cast<std::uint32_t>(status) ==
                       static_cast<std::uint32_t>(SCARD_E_TIMEOUT)) {
                category = ErrorCode::timeout;
            } else if (static_cast<std::uint32_t>(status) ==
                       static_cast<std::uint32_t>(SCARD_E_CANCELLED)) {
                category = ErrorCode::cancelled;
            }

            return {category,
                    "PC/SC operation failed (status " +
                        std::to_string(static_cast<std::uint32_t>(status)) + ")",
                    outcome};
        }

        /**
         * @brief Keep the service context alive until its final reader connection closes.
         *
         * A Provider and every Connection retain shared ownership. This makes SCardReleaseContext
         * occur only after SCardDisconnect has released the final connected card handle.
         */
        struct Context {
            SCARDCONTEXT handle{};
            bool established{false};

            /**
             * @brief Release an established PC/SC service context exactly once.
             *
             * PC/SC cleanup cannot report a useful recovery path during object destruction, so
             * its return value is deliberately ignored after all retained connection owners end.
             */
            ~Context() {
                if (established) {
                    SCardReleaseContext(handle);
                }
            }
        };

        /**
         * @brief Serialize system calls for one activated PC/SC card connection.
         *
         * This adapter handles transport errors only. Native DESFire statuses stay
         * in the returned bytes for interpretation by the selected protocol engine.
         */
        class Connection final : public CardTransport {
        public:

            /**
             * @brief Take ownership of one successfully opened PC/SC card connection.
             * @param context Service context retained until this connection closes.
             * @param card Connected card handle returned by SCardConnect.
             * @param protocol Active T=0 or T=1 protocol returned by SCardConnect.
             */
            Connection(std::shared_ptr<Context> context, SCARDHANDLE card, DWORD protocol)
                : context_(std::move(context)), card_(card), protocol_(protocol) {}

            /**
             * @brief Disconnect while leaving card power and disposition under PC/SC control.
             *
             * A local SDK owner must not silently reset or power down a card that another PC/SC
             * client may still use. The service context remains retained until this destructor
             * completes and the final shared Context owner is released.
             */
            ~Connection() override {
                // Closing an SDK owner must not silently reset or power down a card
                // potentially in use by another PC/SC client.
                SCardDisconnect(card_, SCARD_LEAVE_CARD);
            }

            /**
             * @brief Report conservative ISO APDU limits for the active PC/SC connection.
             * @return ISO 7816 framing limits without cancellation or RF-timing claims.
             */
            TransportCapabilities capabilities() const override {
                TransportCapabilities result;
                result.framing = Framing::iso7816;
                result.max_transmit = 261;
                result.max_receive = 65538;
                result.max_native_frame = 60;
                result.can_reset = true;
                result.can_cancel = false;
                result.hardware_timing = false;
                return result;
            }

            /**
             * @brief Report the generation invalidated by reset or card-removal evidence.
             * @return Monotonic connection generation for managed-session validation.
             */
            std::uint64_t generation() const noexcept override {
                return generation_.load();
            }

            /**
             * @brief Transmit one already framed ISO APDU without retrying it.
             * @param frame Complete APDU borrowed for the duration of SCardTransmit.
             * @param options Positive deadline budget and cooperative stop request.
             * @return Complete response APDU or transport evidence with an unknown delivery result.
             *
             * PC/SC exposes no portable SCardTransmit deadline parameter. A preflight stop or
             * invalid local bound is therefore not sent; any returned PC/SC failure or elapsed
             * overrun is reported as unknown because the reader may already have delivered bytes.
             */
            Result<Bytes> exchange(ByteView frame, const ExchangeOptions& options) override {
                std::lock_guard lock(mutex_);

                if (options.stop.stop_requested()) {
                    return Error{ErrorCode::cancelled, "Cancelled before PC/SC transmission"};
                }

                if (options.timeout.count() <= 0 || frame.size() > capabilities().max_transmit) {
                    return invalid("PC/SC exchange exceeds configured limits");
                }

                Bytes response(capabilities().max_receive);
                DWORD response_size = static_cast<DWORD>(response.size());
                const SCARD_IO_REQUEST request{protocol_, sizeof(SCARD_IO_REQUEST)};
                const auto started = std::chrono::steady_clock::now();
                const LONG status =
                    SCardTransmit(card_, &request, frame.data(), static_cast<DWORD>(frame.size()),
                                  nullptr, response.data(), &response_size);

                if (status != SCARD_S_SUCCESS) {
                    auto error = pcsc_error(status, Outcome::unknown);

                    if (error.code == ErrorCode::card_removed) {
                        generation_.fetch_add(1);
                    }

                    return error;
                }

                // Portable PC/SC cannot force a blocked transmit to return. Once it
                // returns late, do not report an operation within its requested budget.
                if (std::chrono::steady_clock::now() - started > options.timeout) {
                    return Error{ErrorCode::timeout, "PC/SC driver exceeded the exchange budget",
                                 Outcome::unknown};
                }

                if (response_size > response.size()) {
                    return Error{ErrorCode::malformed_response,
                                 "PC/SC returned an oversized response", Outcome::unknown};
                }

                response.resize(response_size);
                return response;
            }

            /**
             * @brief Leave cancellation unavailable for ordinary PC/SC APDU exchange.
             *
             * SCardCancel portably affects status-change waits, not SCardTransmit. The empty
             * implementation preserves the advertised `can_cancel == false` capability.
             */
            void cancel() noexcept override {
                // SCardCancel portably cancels status-change waits, not SCardTransmit.
                // Advertising interruptible APDU I/O here would be misleading.
            }

            /**
             * @brief Reset and reconnect the card, invalidating prior managed state first.
             * @return Success after SCardReconnect updates the active protocol, or unknown
             *         transport evidence when the reset outcome cannot be established.
             */
            Result<void> reset() override {
                std::lock_guard lock(mutex_);
                generation_.fetch_add(1);
                DWORD protocol = 0;
                const LONG status =
                    SCardReconnect(card_, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                   SCARD_RESET_CARD, &protocol);

                if (status != SCARD_S_SUCCESS) {
                    return pcsc_error(status, Outcome::unknown);
                }

                protocol_ = protocol;
                return {};
            }

        private:

            std::shared_ptr<Context> context_;
            SCARDHANDLE card_;
            DWORD protocol_;
            std::mutex mutex_;
            std::atomic<std::uint64_t> generation_{1};
        };

        /** @brief Discover readers without opening an arbitrary default device. */
        class Provider final : public ReaderProvider {
        public:

            /**
             * @brief Retain an established PC/SC service context for discovery and connections.
             * @param context Shared service context that outlives every opened Connection.
             */
            explicit Provider(std::shared_ptr<Context> context) : context_(std::move(context)) {}

            /**
             * @brief Enumerate the current PC/SC reader multi-string without selecting a card.
             * @return Stable reader IDs/names, an empty vector when no readers are available, or
             *         redacted discovery evidence.
             *
             * PC/SC can change the required multi-string capacity between the sizing and fill
             * calls. This safe discovery operation re-queries once; it never retries an APDU or
             * card mutation. A malformed or repeatedly changing result remains a local failure.
             */
            Result<std::vector<ReaderInfo>> readers() override {
                constexpr std::size_t max_reader_list_bytes = std::size_t{1024} * 1024;
                constexpr unsigned max_list_attempts = 2;

                for (unsigned attempt = 0; attempt < max_list_attempts; ++attempt) {
                    DWORD size = 0;
#if defined(_WIN32)
                    LONG status = SCardListReadersA(context_->handle, nullptr, nullptr, &size);
#else
                    LONG status = SCardListReaders(context_->handle, nullptr, nullptr, &size);
#endif
                    if (static_cast<std::uint32_t>(status) ==
                        static_cast<std::uint32_t>(SCARD_E_NO_READERS_AVAILABLE)) {
                        return std::vector<ReaderInfo>{};
                    }

                    if (status != SCARD_S_SUCCESS) {
                        return pcsc_error(status);
                    }

                    if (size == 0) {
                        return std::vector<ReaderInfo>{};
                    }

                    if (size > max_reader_list_bytes) {
                        return Error{ErrorCode::malformed_response,
                                     "PC/SC reader list is oversized"};
                    }

                    std::vector<char> names(size);
#if defined(_WIN32)
                    status = SCardListReadersA(context_->handle, nullptr, names.data(), &size);
#else
                    status = SCardListReaders(context_->handle, nullptr, names.data(), &size);
#endif
                    if (static_cast<std::uint32_t>(status) ==
                        static_cast<std::uint32_t>(SCARD_E_NO_READERS_AVAILABLE)) {
                        return std::vector<ReaderInfo>{};
                    }

                    const bool requires_larger_buffer =
                        static_cast<std::uint32_t>(status) ==
                            static_cast<std::uint32_t>(SCARD_E_INSUFFICIENT_BUFFER) ||
                        size > names.size();
                    if (requires_larger_buffer && attempt + 1 < max_list_attempts) {
                        continue;
                    }
                    if (requires_larger_buffer) {
                        return Error{ErrorCode::transport,
                                     "PC/SC reader list changed during discovery"};
                    }
                    if (status != SCARD_S_SUCCESS) {
                        return pcsc_error(status);
                    }
                    if (size == 0) {
                        return std::vector<ReaderInfo>{};
                    }
                    names.resize(size);
                    if (names.back() != '\0') {
                        return Error{ErrorCode::malformed_response,
                                     "PC/SC reader list is not NUL-terminated"};
                    }

                    std::vector<ReaderInfo> result;
                    std::size_t offset = 0;

                    while (offset < names.size() && names[offset] != '\0') {
                        const auto first = names.begin() + static_cast<std::ptrdiff_t>(offset);
                        const auto end = std::find(first, names.end(), '\0');

                        if (end == names.end()) {
                            return Error{ErrorCode::malformed_response,
                                         "Unterminated PC/SC reader name"};
                        }

                        std::string name(first, end);
                        result.push_back({name, name});
                        offset += name.size() + 1;
                    }

                    const auto terminal = names.begin() + static_cast<std::ptrdiff_t>(offset);
                    if (!std::all_of(terminal, names.end(),
                                     [](char value) { return value == '\0'; })) {
                        return Error{ErrorCode::malformed_response,
                                     "PC/SC reader list has data after its terminator"};
                    }

                    return result;
                }

                return Error{ErrorCode::internal, "PC/SC reader discovery exhausted its attempts"};
            }

            /**
             * @brief Open an explicitly selected PC/SC reader without choosing a default device.
             * @param id Provider-local reader ID previously returned by readers().
             * @return Shared APDU transport retaining its PC/SC connection and service context.
             *
             * Allocation failure after SCardConnect disconnects the temporary card handle, so a
             * failed open cannot leak a connection into the PC/SC resource manager.
             */
            Result<std::shared_ptr<CardTransport>> open(std::string_view id) override {
                if (id.empty() || id.find('\0') != std::string_view::npos) {
                    return invalid("A nonempty PC/SC reader identifier is required");
                }

                const std::string name(id);
                SCARDHANDLE card{};
                DWORD protocol = 0;
#if defined(_WIN32)
                const LONG status =
                    SCardConnectA(context_->handle, name.c_str(), SCARD_SHARE_SHARED,
                                  SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &protocol);
#else
                const LONG status =
                    SCardConnect(context_->handle, name.c_str(), SCARD_SHARE_SHARED,
                                 SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &protocol);
#endif
                if (status != SCARD_S_SUCCESS) {
                    return pcsc_error(status);
                }

                try {
                    return std::shared_ptr<CardTransport>(
                        std::make_shared<Connection>(context_, card, protocol));
                } catch (...) {
                    // Do not leak a connected PC/SC card if native allocation fails.
                    SCardDisconnect(card, SCARD_LEAVE_CARD);
                    throw;
                }
            }

        private:

            std::shared_ptr<Context> context_;
        };

    } // namespace

    /**
     * @brief Establish a PC/SC service context and return an explicit reader provider.
     * @return Provider retaining the service context, or redacted service-start failure evidence.
     *
     * No reader enumeration, card connection, or APDU exchange occurs here. The Provider and any
     * Connection it opens share the Context so cleanup remains ordered even if the provider closes
     * before its last transport.
     */
    Result<std::shared_ptr<ReaderProvider>> pcsc_provider() {
        auto context = std::make_shared<Context>();
        const LONG status =
            SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &context->handle);

        if (status != SCARD_S_SUCCESS) {
            return pcsc_error(status);
        }

        context->established = true;
        return std::shared_ptr<ReaderProvider>(std::make_shared<Provider>(std::move(context)));
    }

} // namespace desfire::transports
