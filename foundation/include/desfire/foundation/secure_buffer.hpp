/**
 * @file
 * @brief Move-only sensitive storage with best-effort erasure.
 */
#pragma once
#include "bytes.hpp"

namespace desfire {

    /**
     * @brief Best-effort overwrite through volatile stores before releasing secret storage.
     * @param bytes Writable storage to overwrite for its current length.
     *
     * This does not erase copies elsewhere or prevent paging and crash-dump exposure.
     */
    void wipe(std::span<Byte> bytes) noexcept;

    /**
     * @brief Move-only, owned bytes wiped on destruction and replacement.
     *
     * Copying is disabled to reduce accidental duplication of keys. Borrowed views remain
     * valid only while this allocation exists and has not been moved or replaced.
     * The class neither locks memory nor provides synchronization between threads.
     */
    class SecureBuffer {
        Bytes bytes_; ///< Owned sensitive byte storage.

    public:

        /**
         * @brief Copy input into owned storage; erasing the original remains the caller's duty.
         * @param data Borrowed bytes copied during construction; the input is not retained.
         */
        explicit SecureBuffer(ByteView data);

        /**
         * @brief Adopt an existing byte allocation without copying sensitive material.
         * @param data Allocation whose ownership transfers to this buffer.
         *
         * The moved-from vector must not be used as a view of this storage. Its former
         * bytes are now erased by this object's destructor or move assignment.
         */
        explicit SecureBuffer(Bytes&& data) noexcept;

        /**
         * @brief Allocate zero-initialized storage, useful for provider output.
         * @param size Number of accessible zero bytes; zero creates an empty buffer.
         */
        explicit SecureBuffer(std::size_t size = 0);

        /**
         * @brief Wipe while the underlying vector still owns its allocation.
         */
        ~SecureBuffer();

        /**
         * @brief Disable copying to reduce accidental duplication of secret bytes.
         * @param other Source buffer that cannot be copied.
         */
        SecureBuffer(const SecureBuffer& other) = delete;

        /**
         * @brief Disable copy replacement to avoid duplicating secret bytes.
         * @param other Source buffer that cannot be copied.
         * @return This buffer; the operation is unavailable.
         */
        SecureBuffer& operator=(const SecureBuffer& other) = delete;

        /**
         * @brief Transfer ownership without deliberately copying secret bytes.
         * @param other Source buffer; its views become invalid after the move.
         */
        SecureBuffer(SecureBuffer&& other) noexcept;

        /**
         * @brief Erase the previous secret before taking ownership of the replacement.
         * @param other Source buffer; its views become invalid after assignment.
         * @return This buffer after it owns the replacement allocation.
         */
        SecureBuffer& operator=(SecureBuffer&& other) noexcept;

        /**
         * @brief Borrow bytes without allocating a copy.
         * @return Read-only view valid until this buffer is moved, replaced, or destroyed.
         */
        [[nodiscard]] ByteView view() const noexcept;

        /**
         * @brief Borrow writable storage; never resize or retain it beyond this buffer's lifetime.
         * @return Mutable view valid until this buffer is moved, replaced, or destroyed.
         */
        std::span<Byte> mutable_view() noexcept;

        /**
         * @brief Number of accessible bytes, independent of the vector's internal capacity.
         * @return Current number of bytes that view() and mutable_view() expose.
         */
        [[nodiscard]] std::size_t size() const noexcept;
    };

} // namespace desfire
