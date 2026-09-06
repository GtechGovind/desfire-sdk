/**
 * @file communication.hpp
 * @brief DESFire native command communication-mode values.
 */
#pragma once

#include <desfire/foundation/bytes.hpp>

namespace desfire::ev3::model {

    /** @brief Native file-operation protection modes and their documented wire values. */
    enum class CommunicationMode : Byte {
        plain = 0, ///< Plain request or response data under the active command policy.
        mac = 1,   ///< Clear data authenticated by the active native session.
        full = 3   ///< Data encrypted and authenticated by the active native session.
    };

} // namespace desfire::ev3::model
