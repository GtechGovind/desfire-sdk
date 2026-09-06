/**
 * @file types.hpp
 * @brief Strong identifiers, settings, byte ownership, and duration conversion for C++17.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <desfire/cpp17/result.hpp>
#include <desfire/raw.h>
#include <limits>
#include <optional>
#include <vector>

namespace desfire::cpp17 {

    /** @brief Owned byte sequence used by the compatibility facade. */
    using Bytes = std::vector<std::uint8_t>;

    /** @brief Default complete-operation timeout used by friendly overloads. */
    inline constexpr std::chrono::milliseconds default_timeout{5000};

    /** @brief Native direct or ISO-wrapped framing selected by a transport. */
    enum class Framing : std::uint32_t {
        native = DF_NATIVE,          /**< Send direct native command frames. */
        iso_wrapped = DF_ISO_WRAPPED /**< Wrap native commands in ISO APDUs. */
    };

    /** @brief Native command and response protection mode. */
    enum class CommunicationMode : std::uint32_t {
        plain = DF_PLAIN, /**< Send command data without secure messaging. */
        mac = DF_MAC,     /**< Authenticate command and response data with a MAC. */
        full = DF_FULL    /**< Encrypt and authenticate command and response data. */
    };

    /** @brief True ISO APDU length-field selection. */
    enum class IsoLengthEncoding : std::uint32_t {
        automatic = DF_ISO_LENGTH_AUTOMATIC,     /**< Select encoding from the APDU lengths. */
        short_length = DF_ISO_LENGTH_SHORT,      /**< Require short ISO length fields. */
        extended_length = DF_ISO_LENGTH_EXTENDED /**< Require extended ISO length fields. */
    };

    /** @brief Secure native session family selected by an explicit raw request. */
    enum class SecureProfile : std::uint32_t {
        none = DF_SECURE_PROFILE_NONE,                 /**< No native secure session. */
        standard_aes = DF_SECURE_PROFILE_STANDARD_AES, /**< Native standard AES session. */
        ev2 = DF_SECURE_PROFILE_EV2                    /**< Native EV2 session. */
    };

    /**
     * @brief Range-checked integer wrapper used to keep protocol identifiers distinct.
     * @tparam Tag Unique semantic tag.
     * @tparam Minimum Inclusive minimum.
     * @tparam Maximum Inclusive maximum.
     */
    template <class Tag, std::uint32_t Minimum, std::uint32_t Maximum> class Identifier final {
    public:

        /**
         * @brief Validate and construct one identifier.
         * @param value Candidate numeric value.
         * @return Strong identifier or a local not-sent argument error.
         */
        static Result<Identifier> make(std::uint32_t value) {
            if (value < Minimum || value > Maximum) {
                return Result<Identifier>::failure(
                    detail::invalid_argument("identifier is outside its documented range"));
            }
            return Result<Identifier>::success(Identifier(value));
        }

        /**
         * @brief Return the checked scalar required by the C ABI.
         * @return The validated scalar value.
         */
        std::uint32_t value() const noexcept {
            return value_;
        }

        /**
         * @brief Compare two values of the same identifier domain for equality.
         * @param left First validated identifier.
         * @param right Second validated identifier.
         * @return True when both identifiers contain the same scalar value.
         */
        friend bool operator==(Identifier left, Identifier right) noexcept {
            return left.value_ == right.value_;
        }

        /**
         * @brief Compare two values of the same identifier domain for inequality.
         * @param left First validated identifier.
         * @param right Second validated identifier.
         * @return True when the identifiers contain different scalar values.
         */
        friend bool operator!=(Identifier left, Identifier right) noexcept {
            return !(left == right);
        }

    private:

        /**
         * @brief Store one value already checked by make().
         * @param value Scalar already checked against this type's valid range.
         */
        explicit Identifier(std::uint32_t value) noexcept : value_(value) {}

        std::uint32_t value_{}; /**< Scalar proven to be within the type-specific range. */
    };

    struct ApplicationIdTag; /**< Type tag for native application identifiers. */
    struct FileNumberTag;    /**< Type tag for native file numbers. */
    struct KeyNumberTag;     /**< Type tag for native and ISO key numbers. */
    struct KeySetNumberTag;  /**< Type tag for EV3 key-set numbers. */
    struct IsoFileIdTag;     /**< Type tag for ISO file identifiers. */
    struct OffsetTag;        /**< Type tag for native byte and record offsets. */
    struct ByteCountTag;     /**< Type tag for bounded native byte counts. */
    struct KeyVersionTag;    /**< Type tag for key-version bytes. */
    struct IsoRecordTag;     /**< Type tag for ISO record numbers. */

    /** @brief Native 24-bit application identifier; zero denotes PICC scope. */
    using ApplicationId = Identifier<ApplicationIdTag, 0, 0xFFFFFF>;

    /** @brief Native file number. */
    using FileNumber = Identifier<FileNumberTag, 0, 31>;

    /** @brief General EV3 key selector; individual commands may impose a tighter range. */
    using KeyNumber = Identifier<KeyNumberTag, 0, 63>;

    /** @brief EV3 key-set selector. */
    using KeySetNumber = Identifier<KeySetNumberTag, 0, 15>;

    /** @brief ISO/IEC 7816 file identifier. */
    using IsoFileId = Identifier<IsoFileIdTag, 0, 0xFFFF>;

    /** @brief Native 24-bit byte or record offset. */
    using Offset = Identifier<OffsetTag, 0, 0xFFFFFF>;

    /** @brief Native 24-bit byte or record count. */
    using ByteCount = Identifier<ByteCountTag, 0, 0xFFFFFF>;

    /** @brief One-byte key version. */
    using KeyVersion = Identifier<KeyVersionTag, 0, 0xFF>;

    /** @brief ISO one-byte record number. */
    using IsoRecord = Identifier<IsoRecordTag, 0, 0xFF>;

    /** @brief Packed native access-right nibbles with explicit raw construction. */
    class AccessRights final {
    public:

        /**
         * @brief Construct from the documented packed 16-bit representation.
         * @param value Raw read/write/read-write/change nibbles.
         * @return Checked access rights.
         */
        static Result<AccessRights> from_raw(std::uint32_t value) {
            if (value > 0xFFFF) {
                return Result<AccessRights>::failure(
                    detail::invalid_argument("access rights exceed sixteen bits"));
            }
            return Result<AccessRights>::success(AccessRights(value));
        }

        /**
         * @brief Return the exact packed value consumed by the C ABI.
         * @return The validated scalar value.
         */
        std::uint32_t value() const noexcept {
            return value_;
        }

    private:

        /**
         * @brief Store one validated packed value.
         * @param value Scalar already checked against this type's valid range.
         */
        explicit AccessRights(std::uint32_t value) noexcept : value_(value) {}

        std::uint32_t value_{}; /**< Validated packed access-rights representation. */
    };

    /** @brief One-byte application key settings with explicit raw construction. */
    class KeySettings final {
    public:

        /**
         * @brief Construct one key-settings byte.
         * @param value Raw settings value.
         * @return Checked settings or a local argument error.
         */
        static Result<KeySettings> from_raw(std::uint32_t value) {
            if (value > 0xFF) {
                return Result<KeySettings>::failure(
                    detail::invalid_argument("key settings exceed one byte"));
            }
            return Result<KeySettings>::success(KeySettings(value));
        }

        /**
         * @brief Return the exact settings byte consumed by the C ABI.
         * @return The validated scalar value.
         */
        std::uint32_t value() const noexcept {
            return value_;
        }

    private:

        /**
         * @brief Store one validated settings byte.
         * @param value Scalar already checked against this type's valid range.
         */
        explicit KeySettings(std::uint32_t value) noexcept : value_(value) {}

        std::uint32_t value_{}; /**< Validated one-byte key-settings representation. */
    };

    namespace detail {

        /**
         * @brief Convert a positive chrono duration without narrowing or unit ambiguity.
         * @param timeout Complete logical-operation timeout.
         * @return Positive C ABI millisecond count or a local not-sent argument error.
         */
        inline Result<std::uint32_t> timeout_milliseconds(std::chrono::milliseconds timeout) {
            const auto count = timeout.count();
            if (count <= 0 ||
                static_cast<std::uint64_t>(count) > std::numeric_limits<std::uint32_t>::max()) {
                return Result<std::uint32_t>::failure(
                    invalid_argument("timeout must fit a positive 32-bit millisecond value"));
            }
            return Result<std::uint32_t>::success(static_cast<std::uint32_t>(count));
        }

        /**
         * @brief Return a nullable C pointer for one borrowed byte vector.
         * @param bytes Byte vector whose storage remains owned by the caller.
         * @return `nullptr` when empty; otherwise a pointer valid until `bytes` is modified or
         * destroyed.
         */
        inline const std::uint8_t* byte_data(const Bytes& bytes) noexcept {
            return bytes.empty() ? nullptr : bytes.data();
        }

    } // namespace detail
} // namespace desfire::cpp17
