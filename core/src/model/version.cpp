/**
 * @file version.cpp
 * @brief Strict DESFire version-response decoding.
 */
#include <desfire/ev3/model/version.hpp>

#include <algorithm>

namespace desfire::ev3::model {

    /** @brief Implement `parse_version` to decode the three-frame card version response. */
    Result<VersionInfo> parse_version(ByteView payload) {
        constexpr std::size_t expected_size = 28;
        constexpr std::size_t hardware_offset = 0;
        constexpr std::size_t software_offset = 7;
        constexpr std::size_t uid_offset = 14;
        constexpr std::size_t batch_offset = 21;
        constexpr std::size_t production_week_offset = 26;
        constexpr std::size_t production_year_offset = 27;

        if (payload.size() != expected_size) {
            return Error{.code = ErrorCode::malformed_response,
                         .message = "GetVersion response must contain exactly 28 bytes",
                         .outcome = Outcome::unknown};
        }

        VersionInfo info{};
        const auto decode_part = [](ByteView bytes) {
            return VersionPart{bytes[0], bytes[1], bytes[2], bytes[3],
                               bytes[4], bytes[5], bytes[6]};
        };
        info.hardware = decode_part(payload.subspan(hardware_offset, 7));
        info.software = decode_part(payload.subspan(software_offset, 7));
        std::ranges::copy(payload.subspan(uid_offset, info.uid.size()), info.uid.begin());
        std::ranges::copy(payload.subspan(batch_offset, info.batch.size()), info.batch.begin());
        info.production_week = payload[production_week_offset];
        info.production_year = payload[production_year_offset];
        return info;
    }

} // namespace desfire::ev3::model
