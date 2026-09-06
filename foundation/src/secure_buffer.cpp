/**
 * @file secure_buffer.cpp
 * @brief Move-only sensitive storage and best-effort erasure implementation.
 */
#include <desfire/foundation/secure_buffer.hpp>

#include <utility>

namespace desfire {

    /** @brief Implement `wipe` to overwrite sensitive storage before release. */
    void wipe(std::span<Byte> bytes) noexcept {
        volatile Byte* output = bytes.data();
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            output[index] = 0;
        }
    }

    /** @brief Implement `SecureBuffer` to construct or transfer owned sensitive storage. */
    SecureBuffer::SecureBuffer(ByteView data) : bytes_(data.begin(), data.end()) {}

    /** @brief Implement `SecureBuffer` to construct or transfer owned sensitive storage. */
    SecureBuffer::SecureBuffer(Bytes&& data) noexcept : bytes_(std::move(data)) {}

    /** @brief Implement `SecureBuffer` to construct or transfer owned sensitive storage. */
    SecureBuffer::SecureBuffer(std::size_t size) : bytes_(size) {}

    /** @brief Implement `~SecureBuffer` to erase owned sensitive bytes before release. */
    SecureBuffer::~SecureBuffer() {
        wipe(bytes_);
    }

    /** @brief Implement `SecureBuffer` to construct or transfer owned sensitive storage. */
    SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : bytes_(std::move(other.bytes_)) {}

    /** @brief Implement move assignment by wiping old bytes before taking replacement ownership. */
    SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            wipe(bytes_);
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }

    /** @brief Implement `view` to expose a read-only view over owned sensitive bytes. */
    ByteView SecureBuffer::view() const noexcept {
        return bytes_;
    }

    /** @brief Implement `mutable_view` to expose writable provider output storage. */
    std::span<Byte> SecureBuffer::mutable_view() noexcept {
        return bytes_;
    }

    /** @brief Implement `size` to report the owned byte count. */
    std::size_t SecureBuffer::size() const noexcept {
        return bytes_.size();
    }

} // namespace desfire
