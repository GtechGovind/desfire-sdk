/**
 * @file identifiers.hpp
 * @brief Range-checked DESFire EV3 identifiers used by checked native commands.
 */
#pragma once

#include <desfire/foundation/bytes.hpp>

#include <cstdint>

namespace desfire::ev3::model {

    /**
     * @brief Store an integer after validating its protocol-specific upper bound.
     * @tparam Tag Unique semantic tag preventing accidental identifier substitution.
     * @tparam Maximum Inclusive maximum accepted by make().
     */
    template <class Tag, std::uint32_t Maximum> class Number {
    public:

        /**
         * @brief Validate an integer before it reaches a narrowing wire encoder.
         * @param value Candidate host value.
         * @return A typed number, or invalid_argument when value exceeds Maximum.
         */
        static Result<Number> make(std::uint32_t value) {
            if (value > Maximum) {
                return invalid("Value exceeds the EV3 field range");
            }
            return Number(value);
        }

        /**
         * @brief Return the previously validated numeric value.
         * @return Value in the inclusive range zero through Maximum.
         */
        [[nodiscard]] constexpr std::uint32_t value() const noexcept {
            return value_;
        }

        /**
         * @brief Compare values with the same protocol meaning.
         * @param other Value to compare.
         * @return True when both validated integers are equal.
         */
        constexpr bool operator==(const Number& other) const = default;

    private:

        /**
         * @brief Retain a value accepted by make().
         * @param value Valid protocol value.
         */
        explicit constexpr Number(std::uint32_t value) noexcept : value_(value) {}

        std::uint32_t value_; ///< Validated numeric value.
    };

    /** @brief Three-byte native application identifier; zero selects the PICC. */
    using ApplicationId = Number<struct ApplicationIdTag, 0x00FFFFFF>;

    /** @brief Native EV3 file number in the five-bit file namespace. */
    using FileNumber = Number<struct FileNumberTag, 31>;

    /** @brief Native EV3 key number before command-specific key-set validation. */
    using KeyNumber = Number<struct KeyNumberTag, 63>;

    /** @brief Three-byte native byte or record offset. */
    using Offset = Number<struct OffsetTag, 0x00FFFFFF>;

    /** @brief Three-byte native byte or record count. */
    using ByteCount = Number<struct ByteCountTag, 0x00FFFFFF>;

} // namespace desfire::ev3::model
