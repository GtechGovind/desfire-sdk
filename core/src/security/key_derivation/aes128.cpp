/**
 * @file aes128.cpp
 * @brief Exact move-only AES-128 key ownership implementation.
 */
#include <desfire/ev3/security/key_derivation/aes128.hpp>

namespace desfire::ev3::security::key_derivation {

    /** @brief Implement `import` to copy exactly sixteen key bytes into protected ownership. */
    Result<Aes128Key> Aes128Key::import(ByteView bytes) {
        if (bytes.size() != aes128_key_size) {
            return invalid("AES-128 key must contain exactly 16 bytes");
        }

        return Aes128Key(SecureBuffer(bytes));
    }

    /** @brief Implement `adopt` to take ownership of an exact sixteen-byte key buffer. */
    Result<Aes128Key> Aes128Key::adopt(SecureBuffer bytes) {
        if (bytes.size() != aes128_key_size) {
            return invalid("AES-128 key must contain exactly 16 bytes");
        }

        return Aes128Key(std::move(bytes));
    }

    /** @brief Borrow the exact key bytes, or an empty moved-from view. */
    ByteView Aes128Key::view() const noexcept {
        return bytes_.view();
    }

    /** @brief Report whether exact key ownership remains after possible moves. */
    bool Aes128Key::valid() const noexcept {
        return bytes_.size() == aes128_key_size;
    }

    /** @brief Provide an out-of-line virtual deriver lifetime boundary. */
    Aes128KeyDeriver::~Aes128KeyDeriver() = default;

    /** @brief Provide an out-of-line virtual provider lifetime boundary. */
    Aes128KeyProvider::~Aes128KeyProvider() = default;

} // namespace desfire::ev3::security::key_derivation
