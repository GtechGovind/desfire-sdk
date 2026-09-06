/**
 * @file raw.hpp
 * @brief Complete result-based C++17 RAII mapping of the split C ABI card and raw channel.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <desfire.h>
#include <desfire/cpp17/key_provider.hpp>
#include <operation_manifest.generated.hpp>
#include <utility>

namespace desfire::cpp17::raw {

    /**
     * @brief Return the loaded C ABI revision without allocating or performing card I/O.
     * @return The ABI version reported by the loaded native library.
     */
    inline std::uint32_t abi_version() noexcept {
        return df_abi_version();
    }

    /**
     * @brief Copy the manifest digest embedded in the loaded C ABI library.
     * @return An owned copy of the requested bytes.
     */
    inline std::string manifest_sha256() {
        const char* digest = df_manifest_sha256();
        return digest == nullptr ? std::string{} : std::string(digest);
    }

    /**
     * @brief Verify that the loaded C library implements this facade's generated operation set.
     * @return Success for the exact ABI and manifest, or a local unsupported error before I/O.
     */
    inline Result<void> validate_native_identity() {
        if (abi_version() != bindings::generated::abi_version ||
            manifest_sha256() != bindings::generated::manifest_sha256) {
            return Result<void>::failure(
                Error{ErrorCode::unsupported, Outcome::not_sent, 0,
                      "loaded C ABI identity does not match the C++17 facade"});
        }
        return Result<void>::success();
    }

    /** @brief Owned C ABI byte buffer released exactly once with df_buffer_free. */
    class Buffer final {
    public:

        /** @brief Construct empty buffer ownership. */
        Buffer() noexcept = default;

        /** @brief Release an owned native buffer. */
        ~Buffer() {
            reset();
        }

        /** @brief Prevent double ownership. */
        Buffer(const Buffer&) = delete;
        /** @brief Prevent double ownership. */
        Buffer& operator=(const Buffer&) = delete;

        /**
         * @brief Transfer native buffer ownership.
         * @param other Source object whose sole ownership is transferred.
         */
        Buffer(Buffer&& other) noexcept : buffer_(std::exchange(other.buffer_, nullptr)) {}

        /**
         * @brief Replace ownership after releasing the current buffer.
         * @param other Source object whose sole ownership is transferred.
         * @return The object that now owns the transferred native resource.
         */
        Buffer& operator=(Buffer&& other) noexcept {
            if (this != &other) {
                reset();
                buffer_ = std::exchange(other.buffer_, nullptr);
            }
            return *this;
        }

        /**
         * @brief Adopt one C ABI buffer returned by an operation.
         * @param buffer Native owned buffer to adopt or inspect.
         * @return A Buffer that takes sole ownership of `buffer`.
         */
        static Buffer adopt(df_buffer* buffer) noexcept {
            return Buffer(buffer);
        }

        /**
         * @brief Return the owned byte count, or zero when empty.
         * @return Number of bytes in the owned native buffer, or zero when empty.
         */
        std::size_t size() const noexcept {
            return df_buffer_size(buffer_);
        }

        /**
         * @brief Borrow immutable native storage until this buffer moves or dies.
         * @return Native storage valid until this Buffer moves, resets, or is destroyed.
         */
        const std::uint8_t* data() const noexcept {
            return df_buffer_data(buffer_);
        }

        /**
         * @brief Copy native bytes into ordinary C++17 ownership without repeating card I/O.
         * @return An owned copy of the requested bytes.
         */
        Bytes copy() const {
            const auto count = size();
            if (count == 0) {
                return {};
            }
            return Bytes(data(), data() + count);
        }

        /**
         * @brief Report whether a native buffer object is owned.
         * @return True while this object owns a native buffer; otherwise false.
         */
        explicit operator bool() const noexcept {
            return buffer_ != nullptr;
        }

    private:

        /**
         * @brief Store one adopted pointer.
         * @param buffer Native owned buffer to adopt or inspect.
         */
        explicit Buffer(df_buffer* buffer) noexcept : buffer_(buffer) {}

        /** @brief Release current storage and become empty. */
        void reset() noexcept {
            if (buffer_ != nullptr) {
                df_buffer_free(buffer_);
                buffer_ = nullptr;
            }
        }

        df_buffer* buffer_{}; /**< Sole native buffer pointer released by this owner. */
    };

    /** @brief Verified public EV2 authentication metadata copied out of C storage. */
    struct AuthenticationInfo final {
        std::array<std::uint8_t, 4>
            transaction_identifier{}; /**< Verified EV2 transaction identifier. */
        std::array<std::uint8_t, 6>
            picc_capabilities{}; /**< Verified six-byte PICC capability record. */
        std::array<std::uint8_t, 6>
            pcd_capabilities{}; /**< Verified six-byte reader capability record. */

        /**
         * @brief Copy the defined public fields from a versioned C record.
         * @param native Versioned C ABI value to copy into C++ ownership.
         * @return Authentication metadata copied into fixed C++ storage.
         */
        static AuthenticationInfo from_native(const df_authentication_info_v1& native) noexcept {
            AuthenticationInfo result;
            std::copy(std::begin(native.transaction_identifier),
                      std::end(native.transaction_identifier),
                      result.transaction_identifier.begin());
            std::copy(std::begin(native.picc_capabilities), std::end(native.picc_capabilities),
                      result.picc_capabilities.begin());
            std::copy(std::begin(native.pcd_capabilities), std::end(native.pcd_capabilities),
                      result.pcd_capabilities.begin());
            return result;
        }
    };

    /** @brief Native status byte and owned status-free response data. */
    struct NativeResponse final {
        std::uint32_t status{}; /**< Exact native status byte returned by the card. */
        Buffer data;            /**< Owned status-free response data. */
    };

    /** @brief ISO status word and owned response data. */
    struct IsoResponse final {
        std::uint16_t status{}; /**< Exact ISO SW1/SW2 status word returned by the card. */
        Buffer data;            /**< Owned status-free response data. */
    };

    /** @brief RAII managed-card handle exposing each managed C ABI operation without
     * reinterpretation. */
    class Card final {
    public:

        /**
         * @brief Open one managed handle without performing card I/O.
         * @param transport Versioned transport descriptor retained according to its callback
         * contract.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        static Result<Card> open(const df_transport_v1& transport) {
            auto identity = validate_native_identity();
            if (!identity) {
                return Result<Card>::failure(std::move(identity).error());
            }
            df_card handle{};
            df_error error{};
            const auto status = df_open(&transport, &handle, &error);
            if (status != DF_OK) {
                return Result<Card>::failure(detail::native_error(status, error));
            }
            return Result<Card>::success(Card(handle));
        }

        /** @brief Best-effort close; use close() when the result must be observed. */
        ~Card() {
            if (handle_ != 0) {
                df_error error{};
                (void)df_close(handle_, &error);
            }
        }

        /** @brief Prevent duplicate native ownership. */
        Card(const Card&) = delete;
        /** @brief Prevent duplicate native ownership. */
        Card& operator=(const Card&) = delete;

        /**
         * @brief Transfer the only native handle owner.
         * @param other Source object whose sole ownership is transferred.
         */
        Card(Card&& other) noexcept : handle_(std::exchange(other.handle_, 0)) {}

        /** @brief Prevent abandoning a live handle during move assignment. */
        Card& operator=(Card&&) = delete;

        /**
         * @brief Close explicitly; DF_BUSY leaves ownership intact.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> close() {
            return lifecycle(df_close, true);
        }

        /**
         * @brief Reset transport and local card state.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> reset() {
            return lifecycle(df_reset, false);
        }

        /**
         * @brief Request cancellation without waiting for the operation lock.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> cancel() {
            return lifecycle(df_cancel, false);
        }

        /**
         * @brief Invalidate state after external replacement.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> notify_state_change() {
            return lifecycle(df_notify_state_change, false);
        }

        /**
         * @brief Borrow the opaque handle for direct interoperability with the same C ABI.
         * @return The borrowed opaque handle; ownership remains with this object.
         */
        df_card native_handle() const noexcept {
            return handle_;
        }

        /**
         * @brief Call `df_get_version` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_version(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_get_version(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_free_memory` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<std::uint32_t> free_memory(uint32_t timeout_ms) {
            df_error error{};
            std::uint32_t out{};
            const auto status = df_free_memory(handle_, timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<std::uint32_t>::failure(detail::native_error(status, error));
            }
            return Result<std::uint32_t>::success(out);
        }

        /**
         * @brief Call `df_select_application` once and preserve its exact C ABI evidence.
         * @param aid Native 24-bit application identifier.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> select_application(uint32_t aid, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_select_application(handle_, aid, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_file_ids` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> file_ids(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_file_ids(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /** @brief Call `df_authenticate_standard_aes` once and preserve its exact C ABI evidence.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> authenticate_standard_aes(uint32_t key_number, const uint8_t* key,
                                               size_t key_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_authenticate_standard_aes(handle_, key_number, key, key_size,
                                                             timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_authenticate_standard_aes_provider` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> authenticate_standard_aes_provider(uint32_t key_number,
                                                        const df_key_provider_v1* provider,
                                                        const df_key_request_v1* request,
                                                        uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_authenticate_standard_aes_provider(handle_, key_number, provider,
                                                                      request, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_authenticate_ev2_first_aes` once and preserve its exact C ABI evidence.
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<AuthenticationInfo> authenticate_ev2_first_aes(uint32_t key_number,
                                                              const uint8_t* key, size_t key_size,
                                                              uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_authenticate_ev2_first_aes(handle_, key_number, key, key_size,
                                                              timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_authenticate_ev2_first_aes_provider` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * evidence. */
        Result<AuthenticationInfo>
        authenticate_ev2_first_aes_provider(uint32_t key_number, const df_key_provider_v1* provider,
                                            const df_key_request_v1* request, uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_authenticate_ev2_first_aes_provider(
                handle_, key_number, provider, request, timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_authenticate_ev2_first_aes_with_capabilities` once and preserve its
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param pcd_capabilities_size Number of bytes available through pcd_capabilities.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * exact C ABI evidence. */
        Result<AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities(
            uint32_t key_number, const uint8_t* key, size_t key_size,
            const uint8_t* pcd_capabilities, size_t pcd_capabilities_size, uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_authenticate_ev2_first_aes_with_capabilities(
                handle_, key_number, key, key_size, pcd_capabilities, pcd_capabilities_size,
                timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_authenticate_ev2_first_aes_with_capabilities_provider` once and preserve
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param pcd_capabilities_size Number of bytes available through pcd_capabilities.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * its exact C ABI evidence. */
        Result<AuthenticationInfo> authenticate_ev2_first_aes_with_capabilities_provider(
            uint32_t key_number, const df_key_provider_v1* provider,
            const df_key_request_v1* request, const uint8_t* pcd_capabilities,
            size_t pcd_capabilities_size, uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_authenticate_ev2_first_aes_with_capabilities_provider(
                handle_, key_number, provider, request, pcd_capabilities, pcd_capabilities_size,
                timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_authenticate_ev2_non_first_aes` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * evidence. */
        Result<AuthenticationInfo> authenticate_ev2_non_first_aes(uint32_t key_number,
                                                                  const uint8_t* key,
                                                                  size_t key_size,
                                                                  uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_authenticate_ev2_non_first_aes(
                handle_, key_number, key, key_size, timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_authenticate_ev2_non_first_aes_provider` once and preserve its exact C
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * ABI evidence. */
        Result<AuthenticationInfo> authenticate_ev2_non_first_aes_provider(
            uint32_t key_number, const df_key_provider_v1* provider,
            const df_key_request_v1* request, uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_authenticate_ev2_non_first_aes_provider(
                handle_, key_number, provider, request, timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /**
         * @brief Call `df_application_ids` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> application_ids(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_application_ids(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_file_ids` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_file_ids(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_file_ids(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_get_key_settings` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_key_settings(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_get_key_settings(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_get_key_set_versions` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_key_set_versions(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_get_key_set_versions(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_get_card_uid` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_card_uid(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_get_card_uid(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /** @brief Call `df_read_originality_signature` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> read_originality_signature(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_read_originality_signature(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_abort_transaction` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> abort_transaction(uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_abort_transaction(handle_, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_format_picc` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> format_picc(uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_format_picc(handle_, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_delete_file` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> delete_file(uint32_t file, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_delete_file(handle_, file, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_get_file_settings` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_file_settings(uint32_t file, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_get_file_settings(handle_, file, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_clear_record_file` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> clear_record_file(uint32_t file, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_clear_record_file(handle_, file, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_get_file_counters` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_file_counters(uint32_t file, uint32_t communication,
                                         uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_get_file_counters(handle_, file, communication, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_delete_application` once and preserve its exact C ABI evidence.
         * @param aid Native 24-bit application identifier.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> delete_application(uint32_t aid, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_delete_application(handle_, aid, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_change_key_settings` once and preserve its exact C ABI evidence.
         * @param settings Packed application key-settings byte to write.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_key_settings(uint32_t settings, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_change_key_settings(handle_, settings, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_get_key_version` once and preserve its exact C ABI evidence.
         * @param number Native key number selected by the command.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_key_version(uint32_t number, int32_t key_set, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_get_key_version(handle_, number, key_set, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_initialize_key_set` once and preserve its exact C ABI evidence.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> initialize_key_set(uint32_t key_set, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_initialize_key_set(handle_, key_set, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_roll_key_set` once and preserve its exact C ABI evidence.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> roll_key_set(uint32_t key_set, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_roll_key_set(handle_, key_set, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_finalize_key_set` once and preserve its exact C ABI evidence.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param version Key version encoded by the command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> finalize_key_set(uint32_t key_set, uint32_t version, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_finalize_key_set(handle_, key_set, version, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_read_data` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> read_data(uint32_t file, uint32_t offset, uint32_t length,
                                 uint32_t communication, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_read_data(handle_, file, offset, length, communication,
                                             timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_write_data` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> write_data(uint32_t file, uint32_t offset, const uint8_t* data, size_t size,
                                uint32_t communication, uint32_t timeout_ms) {
            df_error error{};
            const auto status =
                df_write_data(handle_, file, offset, data, size, communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_write_record` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> write_record(uint32_t file, uint32_t offset, const uint8_t* data, size_t size,
                                  uint32_t communication, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_write_record(handle_, file, offset, data, size, communication,
                                                timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_read_records` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param first Zero-based index of the first native record to return.
         * @param count Maximum number of native records to return.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> read_records(uint32_t file, uint32_t first, uint32_t count,
                                    uint32_t communication, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_read_records(handle_, file, first, count, communication,
                                                timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_update_record` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param record Record number selected by the native or ISO command.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> update_record(uint32_t file, uint32_t record, uint32_t offset,
                                   const uint8_t* data, size_t size, uint32_t communication,
                                   uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_update_record(handle_, file, record, offset, data, size,
                                                 communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_credit` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> credit(uint32_t file, uint32_t amount, uint32_t communication,
                            uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_credit(handle_, file, amount, communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_debit` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> debit(uint32_t file, uint32_t amount, uint32_t communication,
                           uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_debit(handle_, file, amount, communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_limited_credit` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param amount Unsigned value adjustment encoded by the credit or debit command.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> limited_credit(uint32_t file, uint32_t amount, uint32_t communication,
                                    uint32_t timeout_ms) {
            df_error error{};
            const auto status =
                df_limited_credit(handle_, file, amount, communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_get_value` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<std::int32_t> get_value(uint32_t file, uint32_t communication, uint32_t timeout_ms) {
            df_error error{};
            std::int32_t output{};
            const auto status =
                df_get_value(handle_, file, communication, timeout_ms, &output, &error);
            if (status != DF_OK) {
                return Result<std::int32_t>::failure(detail::native_error(status, error));
            }
            return Result<std::int32_t>::success(output);
        }

        /**
         * @brief Call `df_commit_transaction` once and preserve its exact C ABI evidence.
         * @param return_mac True to request transaction-MAC evidence from the commit.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> commit_transaction(uint32_t return_mac, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_commit_transaction(handle_, return_mac, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_commit_reader_id` once and preserve its exact C ABI evidence.
         * @param reader_id Borrowed ReaderID bytes committed with the current transaction.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> commit_reader_id(const uint8_t* reader_id, size_t size,
                                        uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_commit_reader_id(handle_, reader_id, size, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_create_application` once and preserve its exact C ABI evidence.
         * @param aid Native 24-bit application identifier.
         * @param key_settings Documented application key-settings byte.
         * @param key_count Encoded AES key-count and key-type byte.
         * @param iso_id Optional ISO file identifier, or the documented absent sentinel.
         * @param df_name Borrowed ISO dedicated-file name bytes.
         * @param df_name_size Number of bytes available through df_name.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_application(uint32_t aid, uint32_t key_settings, uint32_t key_count,
                                        int32_t iso_id, const uint8_t* df_name, size_t df_name_size,
                                        uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_create_application(handle_, aid, key_settings, key_count, iso_id,
                                                      df_name, df_name_size, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_create_data_file` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param communication Communication mode required by the target file.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param iso_id Optional ISO file identifier, or the documented absent sentinel.
         * @param backup Nonzero creates a transactional backup file; zero creates a standard file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_data_file(uint32_t file, uint32_t length, uint32_t communication,
                                      uint32_t access_rights, int32_t iso_id, uint32_t backup,
                                      uint32_t timeout_ms) {
            df_error error{};
            const auto status =
                df_create_data_file(handle_, file, length, communication, access_rights, iso_id,
                                    backup, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_create_value_file` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param lower_limit Minimum signed value accepted by the value file.
         * @param upper_limit Maximum signed value accepted by the value file.
         * @param initial_value Initial signed value stored when the value file is created.
         * @param communication Communication mode required by the target file.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param limited_credit Nonzero enables limited-credit operations on the value file.
         * @param free_get_value Nonzero permits GetValue without prior authentication when card
         * policy allows it.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_value_file(uint32_t file, int32_t lower_limit, int32_t upper_limit,
                                       int32_t initial_value, uint32_t communication,
                                       uint32_t access_rights, uint32_t limited_credit,
                                       uint32_t free_get_value, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_create_value_file(
                handle_, file, lower_limit, upper_limit, initial_value, communication,
                access_rights, limited_credit, free_get_value, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_create_record_file` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param record_size Number of bytes available through record.
         * @param maximum_records Maximum number of records retained by the file.
         * @param communication Communication mode required by the target file.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param iso_id Optional ISO file identifier, or the documented absent sentinel.
         * @param cyclic Nonzero creates a cyclic record file; zero creates a linear record file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_record_file(uint32_t file, uint32_t record_size,
                                        uint32_t maximum_records, uint32_t communication,
                                        uint32_t access_rights, int32_t iso_id, uint32_t cyclic,
                                        uint32_t timeout_ms) {
            df_error error{};
            const auto status =
                df_create_record_file(handle_, file, record_size, maximum_records, communication,
                                      access_rights, iso_id, cyclic, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_change_file_settings` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param communication Communication mode required by the target file.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param command_communication Secure messaging mode used to protect ChangeFileSettings
         * itself.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_file_settings(uint32_t file, uint32_t communication,
                                          uint32_t access_rights, uint32_t command_communication,
                                          uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_change_file_settings(handle_, file, communication, access_rights,
                                                        command_communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_create_transaction_mac_file` once and preserve its exact C ABI evidence.
         * @param file Native file number targeted by the command.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param version Key version encoded by the command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> create_transaction_mac_file(uint32_t file, uint32_t access_rights,
                                                 const uint8_t* key, size_t key_size,
                                                 uint32_t version, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_create_transaction_mac_file(
                handle_, file, access_rights, key, key_size, version, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_change_aes_key` once and preserve its exact C ABI evidence.
         * @param number Native key number selected by the command.
         * @param new_key Replacement AES-128 key bytes borrowed until return.
         * @param new_key_size Number of bytes available through new_key.
         * @param version Key version encoded by the command.
         * @param authenticated_key Native key number that established the current authenticated
         * session.
         * @param old_key Optional current AES-128 key bytes borrowed until return.
         * @param old_key_size Number of bytes available through old_key.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param picc_master Nonzero uses PICC master-key encoding; zero uses application-key
         * encoding.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_aes_key(uint32_t number, const uint8_t* new_key, size_t new_key_size,
                                    uint32_t version, uint32_t authenticated_key,
                                    const uint8_t* old_key, size_t old_key_size, int32_t key_set,
                                    uint32_t picc_master, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_change_aes_key(handle_, number, new_key, new_key_size, version,
                                                  authenticated_key, old_key, old_key_size, key_set,
                                                  picc_master, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_iso_select_file` once and preserve its exact C ABI evidence.
         * @param identifier ISO file identifier used for selection.
         * @param selection ISO P2 file-selection control byte.
         * @param response Native response descriptor populated by the C ABI.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_select_file(uint32_t identifier, uint32_t selection, uint32_t response,
                                       uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_select_file(handle_, identifier, selection, response,
                                                   timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_select_df_name` once and preserve its exact C ABI evidence.
         * @param name Borrowed ISO dedicated-file name bytes.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param response Native response descriptor populated by the C ABI.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_select_df_name(const uint8_t* name, size_t size, uint32_t response,
                                          uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_iso_select_df_name(handle_, name, size, response, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_read_binary` once and preserve its exact C ABI evidence.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_read_binary(int32_t short_identifier, uint32_t offset, uint32_t length,
                                       uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_read_binary(handle_, short_identifier, offset, length,
                                                   timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_update_binary` once and preserve its exact C ABI evidence.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param offset Zero-based byte offset within the selected file or record.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_update_binary(int32_t short_identifier, uint32_t offset,
                                         const uint8_t* data, size_t size, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_update_binary(handle_, short_identifier, offset, data, size,
                                                     timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_read_records` once and preserve its exact C ABI evidence.
         * @param record Record number selected by the native or ISO command.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param selection ISO P2 file-selection control byte.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_read_records(uint32_t record, uint32_t short_identifier,
                                        uint32_t selection, uint32_t length, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_read_records(handle_, record, short_identifier, selection,
                                                    length, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_append_record` once and preserve its exact C ABI evidence.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_append_record(uint32_t short_identifier, const uint8_t* data,
                                         size_t size, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_append_record(handle_, short_identifier, data, size,
                                                     timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_iso_get_challenge` once and preserve its exact C ABI evidence.
         * @param length Requested byte count; zero retains the command-specific remaining-data
         * meaning.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_get_challenge(uint32_t length, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_get_challenge(handle_, length, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /** @brief Call `df_iso_external_authenticate` once and preserve its exact C ABI evidence.
         * @param number Native key number selected by the command.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param algorithm ISO authentication algorithm reference byte.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_external_authenticate(uint32_t number, uint32_t application,
                                                 uint32_t algorithm, const uint8_t* data,
                                                 size_t size, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_external_authenticate(
                handle_, number, application, algorithm, data, size, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /** @brief Call `df_iso_internal_authenticate` once and preserve its exact C ABI evidence.
         * @param number Native key number selected by the command.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param algorithm ISO authentication algorithm reference byte.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param size Number of bytes available through the immediately preceding pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_internal_authenticate(uint32_t number, uint32_t application,
                                                 uint32_t algorithm, const uint8_t* data,
                                                 size_t size, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_internal_authenticate(
                handle_, number, application, algorithm, data, size, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_authenticate_iso_aes` once and preserve its exact C ABI evidence.
         * @param number Native key number selected by the command.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> authenticate_iso_aes(uint32_t number, uint32_t application, const uint8_t* key,
                                          size_t key_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_authenticate_iso_aes(handle_, number, application, key, key_size,
                                                        timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_authenticate_iso_aes_provider` once and preserve its exact C ABI
         * @param number Native key number selected by the command.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> authenticate_iso_aes_provider(uint32_t number, uint32_t application,
                                                   const df_key_provider_v1* provider,
                                                   const df_key_request_v1* request,
                                                   uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_authenticate_iso_aes_provider(
                handle_, number, application, provider, request, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_get_df_names` once and preserve its exact C ABI evidence.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_df_names(uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_get_df_names(handle_, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_reset_authentication` once and preserve its exact C ABI evidence.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> reset_authentication() {
            df_error error{};
            const auto status = df_reset_authentication(handle_, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_restore_transfer` once and preserve its exact C ABI evidence.
         * @param target_file Native destination file number for RestoreTransfer.
         * @param source_file Native source file number for RestoreTransfer.
         * @param communication Communication mode required by the target file.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> restore_transfer(uint32_t target_file, uint32_t source_file,
                                      uint32_t communication, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_restore_transfer(handle_, target_file, source_file,
                                                    communication, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_create_delegated_application` once and preserve its exact C ABI
         * @param aid Native 24-bit application identifier.
         * @param key_settings Documented application key-settings byte.
         * @param number_of_keys Encoded AES key-count and key-type byte.
         * @param slot Delegated-application slot number.
         * @param slot_version Version assigned to the delegated-application slot.
         * @param quota_limit Maximum delegated storage quota encoded by the command.
         * @param iso_file_identifiers Nonzero enables ISO file identifiers in the delegated
         * application.
         * @param key_settings3 Optional third application key-settings byte, or the absent
         * sentinel.
         * @param iso_id Optional ISO file identifier, or the documented absent sentinel.
         * @param df_name Borrowed ISO dedicated-file name bytes.
         * @param df_name_size Number of bytes available through df_name.
         * @param encrypted_default_key Documented encrypted delegated default-key record.
         * @param encrypted_default_key_size Number of bytes available through
         * encrypted_default_key.
         * @param dam_mac Issuer-generated delegated-application authorization MAC.
         * @param dam_mac_size Number of bytes available through dam_mac.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> create_delegated_application(
            uint32_t aid, uint32_t key_settings, uint32_t number_of_keys, uint32_t slot,
            uint32_t slot_version, uint32_t quota_limit, uint32_t iso_file_identifiers,
            int32_t key_settings3, int32_t iso_id, const uint8_t* df_name, size_t df_name_size,
            const uint8_t* encrypted_default_key, size_t encrypted_default_key_size,
            const uint8_t* dam_mac, size_t dam_mac_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_create_delegated_application(
                handle_, aid, key_settings, number_of_keys, slot, slot_version, quota_limit,
                iso_file_identifiers, key_settings3, iso_id, df_name, df_name_size,
                encrypted_default_key, encrypted_default_key_size, dam_mac, dam_mac_size,
                timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_get_delegated_application_info` once and preserve its exact C ABI
         * @param slot Delegated-application slot number.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * evidence. */
        Result<df_delegated_application_info_v1>
        get_delegated_application_info(uint32_t slot, uint32_t timeout_ms) {
            df_error error{};
            df_delegated_application_info_v1 output{};
            output.struct_size = sizeof(output);
            output.abi_version = DF_ABI_VERSION;
            const auto status =
                df_get_delegated_application_info(handle_, slot, timeout_ms, &output, &error);
            if (status != DF_OK) {
                return Result<df_delegated_application_info_v1>::failure(
                    detail::native_error(status, error));
            }
            return Result<df_delegated_application_info_v1>::success(output);
        }

        /** @brief Call `df_delete_delegated_application` once and preserve its exact C ABI
         * @param aid Native 24-bit application identifier.
         * @param dam_mac Issuer-generated delegated-application authorization MAC.
         * @param dam_mac_size Number of bytes available through dam_mac.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> delete_delegated_application(uint32_t aid, const uint8_t* dam_mac,
                                                  size_t dam_mac_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_delete_delegated_application(handle_, aid, dam_mac, dam_mac_size,
                                                                timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_get_card_uid_variant` once and preserve its exact C ABI evidence.
         * @param option Documented UID/NUID response selector.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> get_card_uid_variant(uint32_t option, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_get_card_uid_variant(handle_, option, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_set_picc_configuration` once and preserve its exact C ABI evidence.
         * @param configuration Named configuration whose fields are encoded by the matching
         * command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_picc_configuration(const df_picc_configuration_v1* configuration,
                                            uint32_t timeout_ms) {
            df_error error{};
            const auto status =
                df_set_picc_configuration(handle_, configuration, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_set_capability_configuration` once and preserve its exact C ABI
         * @param capabilities Exact nine-byte PICC capability configuration record.
         * @param capabilities_size Number of bytes available through capabilities.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> set_capability_configuration(const uint8_t* capabilities,
                                                  size_t capabilities_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_set_capability_configuration(
                handle_, capabilities, capabilities_size, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_set_default_aes_key` once and preserve its exact C ABI evidence.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param key_version Version byte assigned to the supplied AES key.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_default_aes_key(const uint8_t* key, size_t key_size, uint32_t key_version,
                                         uint32_t timeout_ms) {
            df_error error{};
            const auto status =
                df_set_default_aes_key(handle_, key, key_size, key_version, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_set_default_aes_key_provider` once and preserve its exact C ABI
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param key_version Version byte assigned to the supplied AES key.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> set_default_aes_key_provider(const df_key_provider_v1* provider,
                                                  const df_key_request_v1* request,
                                                  uint32_t key_version, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_set_default_aes_key_provider(handle_, provider, request,
                                                                key_version, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_set_ats` once and preserve its exact C ABI evidence.
         * @param ats Complete ATS bytes, including the encoded length byte.
         * @param ats_size Number of bytes available through ats.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_ats(const uint8_t* ats, size_t ats_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_set_ats(handle_, ats, ats_size, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_set_atqa` once and preserve its exact C ABI evidence.
         * @param atqa Two-byte user ATQA value widened to an unsigned integer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> set_atqa(uint32_t atqa, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_set_atqa(handle_, atqa, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_iso_update_record` once and preserve its exact C ABI evidence.
         * @param instruction ISO UPDATE RECORD instruction byte.
         * @param record Record number selected by the native or ISO command.
         * @param short_identifier ISO short file identifier, using zero when the current file
         * applies.
         * @param reference_control ISO P2 record-reference control byte.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param data_size Number of bytes available through data.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> iso_update_record(uint32_t instruction, uint32_t record,
                                         uint32_t short_identifier, uint32_t reference_control,
                                         const uint8_t* data, size_t data_size,
                                         uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_iso_update_record(handle_, instruction, record, short_identifier,
                                                     reference_control, data, data_size, timeout_ms,
                                                     &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_execute_transaction` once and preserve its exact C ABI evidence.
         * @param operations Ordered checked mutations to execute before the commit.
         * @param operation_count Number of checked mutation descriptors in the transaction plan.
         * @param return_mac True to request transaction-MAC evidence from the commit.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> execute_transaction(const df_transaction_operation_v1* operations,
                                           size_t operation_count, uint32_t return_mac,
                                           uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status = df_execute_transaction(handle_, operations, operation_count,
                                                       return_mac, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

        /**
         * @brief Call `df_change_aes_key_provider` once and preserve its exact C ABI evidence.
         * @param number Native key number selected by the command.
         * @param new_key_provider Provider used to resolve the replacement AES key before card I/O.
         * @param new_key_request Scoped request for the replacement AES key.
         * @param version Key version encoded by the command.
         * @param authenticated_key Native key number that established the current authenticated
         * session.
         * @param old_key_provider Optional provider for the current AES key needed by ChangeKey.
         * @param old_key_request Optional scoped request for the current AES key.
         * @param key_set Key-set number selected by the command, or the documented absent sentinel.
         * @param picc_master Nonzero uses PICC master-key encoding; zero uses application-key
         * encoding.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> change_aes_key_provider(
            uint32_t number, const df_key_provider_v1* new_key_provider,
            const df_key_request_v1* new_key_request, uint32_t version, uint32_t authenticated_key,
            const df_key_provider_v1* old_key_provider, const df_key_request_v1* old_key_request,
            int32_t key_set, uint32_t picc_master, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_change_aes_key_provider(
                handle_, number, new_key_provider, new_key_request, version, authenticated_key,
                old_key_provider, old_key_request, key_set, picc_master, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_create_transaction_mac_file_provider` once and preserve its exact C ABI
         * @param file Native file number targeted by the command.
         * @param access_rights Packed 16-bit read, write, read-write, and change access nibbles.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param version Key version encoded by the command.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> create_transaction_mac_file_provider(uint32_t file, uint32_t access_rights,
                                                          const df_key_provider_v1* provider,
                                                          const df_key_request_v1* request,
                                                          uint32_t version, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_create_transaction_mac_file_provider(
                handle_, file, access_rights, provider, request, version, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

    private:

        /**
         * @brief Adopt one successfully opened native handle.
         * @param handle Sole native handle adopted by this facade object.
         */
        explicit Card(df_card handle) noexcept : handle_(handle) {}

        /**
         * @brief Call one lifecycle function and clear ownership only after successful close.
         * @param function C ABI lifecycle function to invoke exactly once.
         * @param closing True when a successful lifecycle call permanently releases the handle.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> lifecycle(std::int32_t (*function)(df_card, df_error*), bool closing) {
            df_error error{};
            const auto status = function(handle_, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            if (closing) {
                handle_ = 0;
            }
            return Result<void>::success();
        }

        df_card handle_{}; /**< Sole opaque native handle released by this owner. */
    };

    /** @brief RAII independent raw channel exposing every raw C ABI operation. */
    class Channel final {
    public:

        /**
         * @brief Open one independent raw channel without card I/O.
         * @param transport Versioned transport descriptor retained according to its callback
         * contract.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        static Result<Channel> open(const df_transport_v1& transport) {
            auto identity = validate_native_identity();
            if (!identity) {
                return Result<Channel>::failure(std::move(identity).error());
            }
            df_raw_channel handle{};
            df_error error{};
            const auto status = df_raw_open(&transport, &handle, &error);
            if (status != DF_OK) {
                return Result<Channel>::failure(detail::native_error(status, error));
            }
            return Result<Channel>::success(Channel(handle));
        }

        /** @brief Best-effort close; use close() when the result must be observed. */
        ~Channel() {
            if (handle_ != 0) {
                df_error error{};
                (void)df_raw_close(handle_, &error);
            }
        }

        /** @brief Prevent duplicate raw-channel ownership. */
        Channel(const Channel&) = delete;
        /** @brief Prevent duplicate raw-channel ownership. */
        Channel& operator=(const Channel&) = delete;

        /**
         * @brief Transfer the only raw-channel owner.
         * @param other Source object whose sole ownership is transferred.
         */
        Channel(Channel&& other) noexcept : handle_(std::exchange(other.handle_, 0)) {}

        /** @brief Prevent abandoning a live raw channel during move assignment. */
        Channel& operator=(Channel&&) = delete;

        /**
         * @brief Close explicitly; DF_BUSY leaves ownership intact.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> close() {
            return lifecycle(df_raw_close, true);
        }

        /**
         * @brief Reset transport and every raw security session.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> reset() {
            return lifecycle(df_raw_reset, false);
        }

        /**
         * @brief Request cancellation without waiting for the operation lock.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> cancel() {
            return lifecycle(df_raw_cancel, false);
        }

        /**
         * @brief Invalidate state after external replacement.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> notify_state_change() {
            return lifecycle(df_raw_notify_state_change, false);
        }

        /**
         * @brief Borrow the opaque handle for direct interoperability with the same C ABI.
         * @return The borrowed opaque handle; ownership remains with this object.
         */
        df_raw_channel native_handle() const noexcept {
            return handle_;
        }

        /**
         * @brief Call `df_raw_native_frame` once and preserve its exact C ABI evidence.
         * @param framing Native direct or ISO-wrapped physical framing selector.
         * @param command Native instruction byte sent in the physical frame.
         * @param data Borrowed operation payload; the call does not retain its storage.
         * @param data_size Number of bytes available through data.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<NativeResponse> native_frame(uint32_t framing, uint32_t command, const uint8_t* data,
                                            size_t data_size, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            std::uint32_t native_status{};
            const auto status = df_raw_native_frame(handle_, framing, command, data, data_size,
                                                    timeout_ms, &native_status, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<NativeResponse>::failure(detail::native_error(status, error));
            }
            return Result<NativeResponse>::success(NativeResponse{native_status, std::move(owned)});
        }

        /**
         * @brief Call `df_raw_native_exchange` once and preserve its exact C ABI evidence.
         * @param request Versioned native logical-exchange descriptor borrowed until return.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<NativeResponse> native_exchange(const df_native_request_v1* request,
                                               uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            std::uint32_t native_status{};
            const auto status = df_raw_native_exchange(handle_, request, timeout_ms, &native_status,
                                                       &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<NativeResponse>::failure(detail::native_error(status, error));
            }
            return Result<NativeResponse>::success(NativeResponse{native_status, std::move(owned)});
        }

        /**
         * @brief Call `df_raw_iso_exchange` once and preserve its exact C ABI evidence.
         * @param request Versioned ISO APDU descriptor borrowed until return.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<IsoResponse> iso_exchange(const df_iso_apdu_v1* request, uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            std::uint32_t iso_status{};
            const auto status =
                df_raw_iso_exchange(handle_, request, timeout_ms, &iso_status, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<IsoResponse>::failure(detail::native_error(status, error));
            }
            return Result<IsoResponse>::success(
                IsoResponse{static_cast<std::uint16_t>(iso_status), std::move(owned)});
        }

        /** @brief Call `df_raw_authenticate_standard_aes` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> authenticate_standard_aes(uint32_t key_number, const uint8_t* key,
                                               size_t key_size, uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_raw_authenticate_standard_aes(handle_, key_number, key, key_size,
                                                                 timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_raw_authenticate_standard_aes_provider` once and preserve its exact C
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * ABI evidence. */
        Result<void> authenticate_standard_aes_provider(uint32_t key_number,
                                                        const df_key_provider_v1* provider,
                                                        const df_key_request_v1* request,
                                                        uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_raw_authenticate_standard_aes_provider(
                handle_, key_number, provider, request, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_raw_authenticate_ev2_first_aes` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param pcd_capabilities_size Number of bytes available through pcd_capabilities.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * evidence. */
        Result<AuthenticationInfo> authenticate_ev2_first_aes(uint32_t key_number,
                                                              const uint8_t* key, size_t key_size,
                                                              const uint8_t* pcd_capabilities,
                                                              size_t pcd_capabilities_size,
                                                              uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_raw_authenticate_ev2_first_aes(
                handle_, key_number, key, key_size, pcd_capabilities, pcd_capabilities_size,
                timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_raw_authenticate_ev2_first_aes_provider` once and preserve its exact C
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param pcd_capabilities Zero through six explicit reader capability bytes.
         * @param pcd_capabilities_size Number of bytes available through pcd_capabilities.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * ABI evidence. */
        Result<AuthenticationInfo>
        authenticate_ev2_first_aes_provider(uint32_t key_number, const df_key_provider_v1* provider,
                                            const df_key_request_v1* request,
                                            const uint8_t* pcd_capabilities,
                                            size_t pcd_capabilities_size, uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_raw_authenticate_ev2_first_aes_provider(
                handle_, key_number, provider, request, pcd_capabilities, pcd_capabilities_size,
                timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_raw_authenticate_ev2_non_first_aes` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * evidence. */
        Result<AuthenticationInfo> authenticate_ev2_non_first_aes(uint32_t key_number,
                                                                  const uint8_t* key,
                                                                  size_t key_size,
                                                                  uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_raw_authenticate_ev2_non_first_aes(
                handle_, key_number, key, key_size, timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /** @brief Call `df_raw_authenticate_ev2_non_first_aes_provider` once and preserve its exact
         * @param key_number Validated native key selector.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         * C ABI evidence. */
        Result<AuthenticationInfo> authenticate_ev2_non_first_aes_provider(
            uint32_t key_number, const df_key_provider_v1* provider,
            const df_key_request_v1* request, uint32_t timeout_ms) {
            df_error error{};
            df_authentication_info_v1 out{};
            out.struct_size = sizeof(out);
            out.abi_version = DF_ABI_VERSION;
            const auto status = df_raw_authenticate_ev2_non_first_aes_provider(
                handle_, key_number, provider, request, timeout_ms, &out, &error);
            if (status != DF_OK) {
                return Result<AuthenticationInfo>::failure(detail::native_error(status, error));
            }
            return Result<AuthenticationInfo>::success(AuthenticationInfo::from_native(out));
        }

        /**
         * @brief Call `df_raw_authenticate_iso_aes` once and preserve its exact C ABI evidence.
         * @param key_number Validated native key selector.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param key Live AES-128 key borrowed only until the operation returns.
         * @param key_size Number of bytes available through the borrowed key pointer.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> authenticate_iso_aes(uint32_t key_number, uint32_t application,
                                          const uint8_t* key, size_t key_size,
                                          uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_raw_authenticate_iso_aes(handle_, key_number, application, key,
                                                            key_size, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /** @brief Call `df_raw_authenticate_iso_aes_provider` once and preserve its exact C ABI
         * @param key_number Validated native key selector.
         * @param application Nonzero selects application-key scope; zero selects PICC master-key
         * scope.
         * @param provider Synchronous key provider invoked before the first card frame.
         * @param request Non-secret key lookup request borrowed for the synchronous provider call.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return Success or owned failure evidence with the exact delivery outcome.
         * evidence. */
        Result<void> authenticate_iso_aes_provider(uint32_t key_number, uint32_t application,
                                                   const df_key_provider_v1* provider,
                                                   const df_key_request_v1* request,
                                                   uint32_t timeout_ms) {
            df_error error{};
            const auto status = df_raw_authenticate_iso_aes_provider(
                handle_, key_number, application, provider, request, timeout_ms, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            return Result<void>::success();
        }

        /**
         * @brief Call `df_raw_iso_secure_exchange` once and preserve its exact C ABI evidence.
         * @param request Versioned ISO APDU descriptor protected by the established ISO AES
         * session.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<IsoResponse> iso_secure_exchange(const df_iso_apdu_v1* request,
                                                uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            std::uint32_t iso_status{};
            const auto status = df_raw_iso_secure_exchange(handle_, request, timeout_ms,
                                                           &iso_status, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<IsoResponse>::failure(detail::native_error(status, error));
            }
            return Result<IsoResponse>::success(
                IsoResponse{static_cast<std::uint16_t>(iso_status), std::move(owned)});
        }

        /** @brief Call `df_raw_native_secure_exchange` once and preserve its exact C ABI evidence.
         * @param request Versioned secure-native request descriptor borrowed until return.
         * @param timeout_ms Positive complete logical-operation timeout in milliseconds.
         * @return The owned success value or failure evidence with the exact delivery outcome.
         */
        Result<Buffer> native_secure_exchange(const df_native_secure_request_v1* request,
                                              uint32_t timeout_ms) {
            df_error error{};
            df_buffer* buffer{};
            const auto status =
                df_raw_native_secure_exchange(handle_, request, timeout_ms, &buffer, &error);
            Buffer owned = Buffer::adopt(buffer);
            if (status != DF_OK) {
                return Result<Buffer>::failure(detail::native_error(status, error));
            }
            return Result<Buffer>::success(std::move(owned));
        }

    private:

        /**
         * @brief Adopt one successfully opened raw handle.
         * @param handle Sole native handle adopted by this facade object.
         */
        explicit Channel(df_raw_channel handle) noexcept : handle_(handle) {}

        /** @brief Call one raw lifecycle function and clear ownership only after successful close.
         * @param function C ABI lifecycle function to invoke exactly once.
         * @param closing True when a successful lifecycle call permanently releases the handle.
         * @return Success or owned failure evidence with the exact delivery outcome.
         */
        Result<void> lifecycle(std::int32_t (*function)(df_raw_channel, df_error*), bool closing) {
            df_error error{};
            const auto status = function(handle_, &error);
            if (status != DF_OK) {
                return Result<void>::failure(detail::native_error(status, error));
            }
            if (closing) {
                handle_ = 0;
            }
            return Result<void>::success();
        }

        df_raw_channel handle_{}; /**< Sole opaque native handle released by this owner. */
    };
} // namespace desfire::cpp17::raw
