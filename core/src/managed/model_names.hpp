/**
 * @file model_names.hpp
 * @brief Narrow private imports used by the managed implementation partitions.
 */
#pragma once

#include <desfire/ev3/model/authentication.hpp>
#include <desfire/ev3/model/settings.hpp>
#include <desfire/ev3/model/version.hpp>
#include <desfire/ev3/native/checked/applications.hpp>
#include <desfire/ev3/native/checked/card_management.hpp>
#include <desfire/ev3/native/checked/command.hpp>
#include <desfire/ev3/native/checked/files.hpp>

namespace desfire::ev3::managed {

    using model::AccessRights;
    using model::ApplicationConfiguration;
    using model::ApplicationId;
    using model::AuthenticationInfo;
    using model::ByteCount;
    using model::CapabilityConfiguration;
    using model::CommunicationMode;
    using model::DataFileConfiguration;
    using model::DelegatedApplicationConfiguration;
    using model::FileNumber;
    using model::FileSettings;
    using model::FileSettingsChange;
    using model::FileType;
    using model::KeyNumber;
    using model::KeySettings;
    using model::Offset;
    using model::PiccConfiguration;
    using model::RecordFileConfiguration;
    using model::ValueFileConfiguration;
    using model::VersionInfo;

    using native::checked::CardUid;
    using native::checked::CardUidRequest;
    using native::checked::Command;
    using native::checked::DelegatedApplicationInfo;
    using native::checked::DfName;
    using native::checked::FileCounters;

} // namespace desfire::ev3::managed
