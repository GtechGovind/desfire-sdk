/**
 * @file ev3.hpp
 * @brief Complete canonical C++ include for the DESFire EV3 core.
 *
 * The umbrella exposes explicit model, raw, checked, secure, offline, ISO/IEC 7816, and managed
 * layers. It contains no compatibility aliases for the removed monolithic API.
 */
#pragma once

#include <desfire/ev3/model/authentication.hpp>
#include <desfire/ev3/model/communication.hpp>
#include <desfire/ev3/model/identifiers.hpp>
#include <desfire/ev3/model/settings.hpp>
#include <desfire/ev3/model/version.hpp>

#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/command.hpp>
#include <desfire/ev3/native/checked/files.hpp>
#include <desfire/ev3/native/checked/keys.hpp>
#include <desfire/ev3/native/checked/transactions.hpp>
#include <desfire/ev3/native/framing.hpp>
#include <desfire/ev3/native/raw/channel.hpp>
#include <desfire/ev3/native/raw/codec.hpp>
#include <desfire/ev3/native/raw/message.hpp>
#include <desfire/ev3/native/secure/channel.hpp>
#include <desfire/ev3/native/secure/request.hpp>

#include <desfire/ev3/security/ev2/authentication.hpp>
#include <desfire/ev3/security/ev2/session.hpp>
#include <desfire/ev3/security/key_derivation/aes128.hpp>
#include <desfire/ev3/security/key_derivation/nxp_aes128.hpp>
#include <desfire/ev3/security/standard_aes/authentication.hpp>
#include <desfire/ev3/security/standard_aes/session.hpp>

#include <desfire/ev3/iso7816/checked/channel.hpp>
#include <desfire/ev3/iso7816/checked/command.hpp>
#include <desfire/ev3/iso7816/checked/response.hpp>
#include <desfire/ev3/iso7816/raw/apdu.hpp>
#include <desfire/ev3/iso7816/raw/channel.hpp>
#include <desfire/ev3/iso7816/raw/codec.hpp>
#include <desfire/ev3/iso7816/security/aes/authentication.hpp>
#include <desfire/ev3/iso7816/security/aes/session.hpp>

#include <desfire/ev3/offline/delegated_application.hpp>
#include <desfire/ev3/offline/mifare_classic_license.hpp>
#include <desfire/ev3/offline/originality_signature.hpp>
#include <desfire/ev3/offline/transaction_mac.hpp>

#include <desfire/ev3/managed/card.hpp>
#include <desfire/ev3/managed/transaction_plan.hpp>
