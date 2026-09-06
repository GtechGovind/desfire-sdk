/**
 * @file framing.hpp
 * @brief Explicit reader framing for DESFire native commands.
 */
#pragma once

namespace desfire::ev3::native {

    /**
     * @brief Select how one DESFire native command is presented to the reader.
     *
     * Direct framing places the native command byte first. ISO-wrapped framing uses the
     * proprietary short APDU form `90 INS 00 00 [Lc Data] 00`. It is distinct from an actual
     * ISO/IEC 7816 command whose class byte is `00`.
     */
    enum class Framing {
        direct,
        iso_wrapped,
    };

} // namespace desfire::ev3::native
