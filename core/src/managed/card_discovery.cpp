/**
 * @file card_discovery.cpp
 * @brief Managed DESFire EV3 discovery and frame-preserving enumeration.
 */
#include <desfire/ev3/managed/card.hpp>

#include "card_impl.hpp"
#include "model_names.hpp"
#include "operation_guard.hpp"

#include <algorithm>
#include <string>

namespace desfire::ev3::managed {

    namespace {

        /**
         * @brief Convert a native discovery rejection into stable evidence.
         * @param status Native status byte.
         * @param operation Redacted discovery operation name.
         * @return Card-rejected error retaining the status byte.
         */
        Error discovery_rejected(Byte status, std::string_view operation) {
            return Error{ErrorCode::card_rejected, std::string(operation) + " was rejected by card",
                         Outcome::rejected, status};
        }

    } // namespace

    /** @brief Read and parse the fixed GetVersion response. */
    Result<model::VersionInfo> Card::get_version(const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        auto payload = execute_plain_locked(0x60, {}, options, "GetVersion");
        if (!payload) {
            return payload.error();
        }
        auto version = model::parse_version(payload.value());
        if (!version) {
            invalidate_locked();
            return version.error();
        }

        return version;
    }

    /** @brief Read and decode the exact three-byte FreeMem response. */
    Result<std::uint32_t> Card::free_memory(const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        auto payload = execute_plain_locked(0x6E, {}, options, "FreeMem");
        if (!payload) {
            return payload.error();
        }
        if (payload.value().size() != 3) {
            invalidate_locked();
            return Error{ErrorCode::malformed_response,
                         "FreeMem response must contain exactly three bytes", Outcome::unknown};
        }

        return get_le(payload.value());
    }

    /** @brief Read and validate unique native file identifiers. */
    Result<std::vector<model::FileNumber>> Card::file_ids(const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        auto payload = execute_plain_locked(0x6F, {}, options, "GetFileIDs");
        if (!payload) {
            return payload.error();
        }
        if (payload.value().size() > 32) {
            invalidate_locked();
            return Error{ErrorCode::malformed_response, "GetFileIDs exceeds DESFire file capacity",
                         Outcome::unknown};
        }

        std::vector<model::FileNumber> files;
        files.reserve(payload.value().size());
        for (const Byte raw_file : payload.value()) {
            auto file = model::FileNumber::make(raw_file);
            if (!file || std::ranges::find(files, file.value()) != files.end()) {
                invalidate_locked();
                return Error{ErrorCode::malformed_response,
                             "GetFileIDs contains an invalid or duplicate file number",
                             Outcome::unknown};
            }
            files.push_back(file.value());
        }

        return files;
    }

    /** @brief Read unauthenticated DF names without concatenating record-bearing frames. */
    Result<std::vector<native::checked::DfName>> Card::df_names(const ExchangeOptions& options) {
        OperationGuard operation(impl_->operation_mutex, impl_->operation_active);
        if (!operation) {
            return Error{ErrorCode::busy, "Card callback cannot reenter an active operation"};
        }

        try {
            if (!impl_->usable || impl_->iso_session) {
                return Error{ErrorCode::session_invalid,
                             "GetDFNames requires usable native card state"};
            }
            if (impl_->authentication_reset_pending) {
                return Error{ErrorCode::session_invalid,
                             "Select an application, authenticate EV2 First, or reset before "
                             "GetDFNames after local authentication reset"};
            }
            if (impl_->has_native_session()) {
                return Error{ErrorCode::authentication,
                             "GetDFNames requires unauthenticated native card state"};
            }
            if (impl_->raw->generation() != impl_->generation) {
                invalidate_locked();
                return Error{ErrorCode::card_removed, "Card changed before GetDFNames"};
            }

            auto transaction = impl_->raw->begin(options);
            if (!transaction) {
                return transaction.error();
            }

            std::vector<Bytes> records;
            Byte command = 0x6D;
            for (std::size_t index = 0; index < 4096; ++index) {
                auto response = transaction.value().exchange_frame(command, {});
                if (!response) {
                    if (response.error().outcome == Outcome::unknown) {
                        invalidate_locked();
                    }
                    return response.error();
                }

                auto& frame = response.value();
                if (frame.status != 0x00 && frame.status != 0xAF) {
                    return discovery_rejected(frame.status, "GetDFNames");
                }
                if (frame.data.size() > 29 ||
                    (frame.status == 0xAF && (frame.data.empty() || frame.data.size() > 21))) {
                    invalidate_locked();
                    return Error{ErrorCode::malformed_response,
                                 "DF-name frame violates its record bound", Outcome::unknown};
                }
                if (!frame.data.empty()) {
                    records.push_back(std::move(frame.data));
                }
                if (frame.status == 0x00) {
                    std::vector<native::checked::DfName> names;
                    names.reserve(records.size());
                    for (const auto& record : records) {
                        auto decoded = native::checked::parse_df_name_frame(record);
                        if (!decoded) {
                            invalidate_locked();
                            return decoded.error();
                        }
                        names.push_back(std::move(decoded.value()));
                    }

                    return names;
                }

                command = 0xAF;
            }

            invalidate_locked();
            return Error{ErrorCode::malformed_response, "DF-name chain exceeded the record limit",
                         Outcome::unknown};
        } catch (...) {
            invalidate_locked();
            return Error{ErrorCode::internal, "DF-name command failed", Outcome::unknown};
        }
    }

} // namespace desfire::ev3::managed
