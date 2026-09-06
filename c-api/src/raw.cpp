/**
 * @file raw.cpp
 * @brief Independent native, true ISO, and explicit secure raw C channels.
 */
#include "detail/internal.hpp"

using namespace desfire;
using namespace desfire::c_api::detail;

namespace {
    /**
     * @brief Report whether all reserved descriptor words are zero.
     * @tparam Size Compile-time number of reserved words.
     * @param reserved Fixed reserved-word array to inspect.
     * @return True only when every reserved word is zero.
     */
    template <std::size_t Size>
    bool reserved_is_zero(const std::uint64_t (&reserved)[Size]) noexcept {
        return std::all_of(std::begin(reserved), std::end(reserved),
                           [](std::uint64_t value) { return value == 0; });
    }

    /**
     * @brief Require that a C framing selector matches a native raw channel.
     * @param entry Retained raw-channel entry.
     * @param framing Caller-selected direct-native or ISO-wrapped framing.
     * @return Success or unsupported/invalid_argument without transport I/O.
     */
    Result<void> require_native_framing(const RawEntry& entry, std::uint32_t framing) {
        if (!entry.native || framing > DF_ISO_WRAPPED) {
            return Error{ErrorCode::unsupported, "Operation requires a native raw channel"};
        }
        const auto selected =
            entry.native->framing() == ev3::native::Framing::direct ? DF_NATIVE : DF_ISO_WRAPPED;
        if (selected != framing) {
            return invalid("Requested native framing does not match the transport");
        }
        return {};
    }

    /**
     * @brief Erase all raw authentication state.
     * @param entry Raw entry whose session objects and generation binding are cleared.
     */
    void clear_sessions(RawEntry& entry) noexcept {
        entry.standard_session.reset();
        entry.ev2_session.reset();
        entry.iso_session.reset();
        entry.session_generation = 0;
    }

    /**
     * @brief Reject a stale session after card generation changes.
     * @param entry Raw entry whose secure session must match the transport generation.
     * @return Success for current state, or session_invalid after erasing stale state.
     */
    Result<void> require_current_session(RawEntry& entry) {
        if (entry.session_generation == 0 ||
            entry.session_generation != entry.transport->generation()) {
            clear_sessions(entry);
            return Error{ErrorCode::session_invalid,
                         "Raw authentication session is absent or stale"};
        }
        return {};
    }

    /**
     * @brief Convert a public ISO APDU descriptor to the owned raw core model.
     * @param input Borrowed versioned APDU descriptor with bounded lengths.
     * @return Owned APDU or invalid_argument before transport I/O.
     */
    Result<ev3::iso7816::raw::Apdu> make_iso_apdu(const df_iso_apdu_v1* input) {
        if (!input || input->struct_size != sizeof(df_iso_apdu_v1) ||
            input->abi_version != DF_ABI_VERSION || input->cla > 0xFFU || input->ins > 0xFFU ||
            input->p1 > 0xFFU || input->p2 > 0xFFU || input->data_size > 65535U ||
            input->has_le > 1U ||
            (input->has_le != 0U && (input->le == 0U || input->le > 65536U)) ||
            input->length_encoding > DF_ISO_LENGTH_EXTENDED || input->correct_length > 1U ||
            input->maximum_response == 0U || input->maximum_frames == 0U ||
            !reserved_is_zero(input->reserved)) {
            return invalid("Invalid raw ISO APDU descriptor");
        }
        auto data = bytes(input->data, input->data_size);
        if (!data) {
            return data.error();
        }
        std::optional<std::uint32_t> le;
        if (input->has_le != 0U) {
            le = input->le;
        }
        return ev3::iso7816::raw::Apdu{
            .cla = static_cast<Byte>(input->cla),
            .ins = static_cast<Byte>(input->ins),
            .p1 = static_cast<Byte>(input->p1),
            .p2 = static_cast<Byte>(input->p2),
            .data = Bytes(data.value().begin(), data.value().end()),
            .le = le,
            .encoding = static_cast<ev3::iso7816::raw::LengthEncoding>(input->length_encoding),
        };
    }

    /**
     * @brief Rebuild a caller APDU through the exact checked ISO command factory.
     * @param apdu Validated raw APDU accepted only for a documented secure ISO operation.
     * @return Checked command or unsupported/invalid_argument without transport I/O.
     */
    Result<ev3::iso7816::checked::Command>
    make_checked_iso_command(const ev3::iso7816::raw::Apdu& apdu) {
        namespace checked = ev3::iso7816::checked;
        if (apdu.cla != 0x00) {
            return invalid("Authenticated ISO command requires CLA 00");
        }
        switch (apdu.ins) {
        case 0xA4:
            if (apdu.p2 != 0x00 && apdu.p2 != 0x0C) {
                return invalid("Invalid ISO selection response selector");
            }
            if (apdu.p1 == 0x04) {
                return checked::Command::select_df_name(
                    apdu.data, static_cast<checked::SelectionResponse>(apdu.p2), apdu.encoding);
            }
            if (apdu.p1 > 0x02 || apdu.data.size() != 2U) {
                return invalid("Invalid ISO file selection APDU");
            }
            return checked::Command::select_file(
                static_cast<std::uint32_t>(apdu.data[0]) << 8U | apdu.data[1],
                static_cast<checked::FileSelection>(apdu.p1),
                static_cast<checked::SelectionResponse>(apdu.p2), apdu.encoding);
        case 0xB0: {
            if (!apdu.le || !apdu.data.empty()) {
                return invalid("ISO READ BINARY requires Le and no command data");
            }
            Result<checked::BinaryAddress> address =
                (apdu.p1 & 0x80U) != 0U
                    ? checked::BinaryAddress::short_file((apdu.p1 >> 3U) & 0x1FU, apdu.p2)
                    : checked::BinaryAddress::current_file(
                          static_cast<std::uint32_t>(apdu.p1) << 8U | apdu.p2);
            if (!address) {
                return address.error();
            }
            return checked::Command::read_binary(address.value(), *apdu.le, apdu.encoding);
        }
        case 0xD6: {
            if (apdu.le) {
                return invalid("ISO UPDATE BINARY cannot carry Le");
            }
            Result<checked::BinaryAddress> address =
                (apdu.p1 & 0x80U) != 0U
                    ? checked::BinaryAddress::short_file((apdu.p1 >> 3U) & 0x1FU, apdu.p2)
                    : checked::BinaryAddress::current_file(
                          static_cast<std::uint32_t>(apdu.p1) << 8U | apdu.p2);
            if (!address) {
                return address.error();
            }
            return checked::Command::update_binary(address.value(), apdu.data, apdu.encoding);
        }
        case 0xB2:
            if (!apdu.le || !apdu.data.empty() ||
                ((apdu.p2 & 0x07U) != 0x04U && (apdu.p2 & 0x07U) != 0x05U)) {
                return invalid("Invalid ISO READ RECORDS APDU");
            }
            return checked::Command::read_records(
                apdu.p1, apdu.p2 >> 3U, static_cast<checked::RecordSelection>(apdu.p2 & 0x07U),
                *apdu.le, apdu.encoding);
        case 0xE2:
            if (apdu.le || apdu.p1 != 0x00 || (apdu.p2 & 0x07U) != 0U) {
                return invalid("Invalid ISO APPEND RECORD APDU");
            }
            return checked::Command::append_record(apdu.p2 >> 3U, apdu.data, apdu.encoding);
        case 0xDC:
        case 0xDD:
            if (apdu.le || apdu.encoding == ev3::iso7816::raw::LengthEncoding::extended) {
                return invalid("ISO UPDATE RECORD requires the checked short form");
            }
            return checked::Command::update_record(
                static_cast<checked::UpdateRecordInstruction>(apdu.ins), apdu.p1, apdu.p2 >> 3U,
                apdu.p2 & 0x07U, apdu.data);
        default:
            return Error{ErrorCode::unsupported,
                         "ISO AES raw session accepts only checked data commands and EF selection"};
        }
    }
} // namespace

extern "C" {

/** @brief Implement the documented `df_raw_open` C ABI operation. */
int32_t df_raw_open(const df_transport_v1* transport, df_raw_channel* out, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!out || *out != 0) {
            return invalid("Output handle must point to zero");
        }
        auto transport_result = make_transport(transport);
        if (!transport_result) {
            return transport_result.error();
        }
        auto crypto = openssl_provider();
        if (!crypto) {
            return crypto.error();
        }
        auto entry = std::make_shared<RawEntry>();
        entry->transport = transport_result.value();
        entry->crypto = crypto.value();
        if (entry->transport->capabilities().framing == Framing::native ||
            entry->transport->capabilities().framing == Framing::iso7816) {
            auto native = ev3::native::raw::RawNativeChannel::connect(entry->transport);
            if (!native) {
                return native.error();
            }
            entry->native = native.value();
            auto secure = ev3::native::secure::SecureNativeChannel::connect(entry->native);
            if (!secure) {
                return secure.error();
            }
            entry->secure = secure.value();
        }
        if (entry->transport->capabilities().framing == Framing::iso7816) {
            auto iso = ev3::iso7816::raw::Channel::create(entry->transport);
            if (!iso) {
                return iso.error();
            }
            entry->iso = std::move(iso.value());
            entry->iso_checked = std::make_unique<ev3::iso7816::checked::Channel>(*entry->iso);
        }
        std::lock_guard lock(raw_registry_mutex);
        if (next_raw_handle == UINT64_MAX) {
            return Error{ErrorCode::internal, "Raw-channel handle space exhausted"};
        }
        const auto handle = next_raw_handle++;
        raw_registry.emplace(handle, std::move(entry));
        *out = handle;
        return {};
    });
}

/** @brief Implement the documented `df_raw_close` C ABI operation. */
int32_t df_raw_close(df_raw_channel channel, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto entry = lookup_raw(channel);
        if (!entry) {
            return entry.error();
        }
        std::unique_lock operation(entry.value()->operation, std::try_to_lock);
        if (!operation.owns_lock() || entry.value()->active) {
            return Error{ErrorCode::busy,
                         "Cancel or wait for the active raw operation before close"};
        }
        std::lock_guard registry_lock(raw_registry_mutex);
        entry.value()->closed = true;
        clear_sessions(*entry.value());
        if (raw_registry.erase(channel) != 1U) {
            return Error{ErrorCode::stale_handle, "Raw channel is already closed"};
        }
        return {};
    });
}

/** @brief Implement the documented `df_raw_reset` C ABI operation. */
int32_t df_raw_reset(df_raw_channel channel, df_error* error) {
    return boundary(error, [&] {
        return invoke_raw(channel, 5000U,
                          [](RawEntry& entry, const ExchangeOptions&) -> Result<void> {
                              clear_sessions(entry);
                              if (entry.iso) {
                                  return entry.iso->reset();
                              }
                              return entry.native->reset();
                          });
    });
}

/** @brief Implement the documented `df_raw_cancel` C ABI operation. */
int32_t df_raw_cancel(df_raw_channel channel, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto entry = lookup_raw(channel);
        if (!entry) {
            return entry.error();
        }
        entry.value()->transport->cancel();
        return {};
    });
}

/** @brief Implement the documented `df_raw_notify_state_change` C ABI operation. */
int32_t df_raw_notify_state_change(df_raw_channel channel, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto entry = lookup_raw(channel);
        if (!entry) {
            return entry.error();
        }
        entry.value()->transport->notify_state_change();
        return {};
    });
}

/** @brief Implement the documented `df_raw_native_frame` C ABI operation. */
int32_t df_raw_native_frame(df_raw_channel channel, uint32_t framing, uint32_t command,
                            const uint8_t* data, size_t data_size, uint32_t timeout_ms,
                            uint32_t* native_status, df_buffer** response, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (command > 0xFFU || !native_status) {
            return invalid("Native command and status output are required");
        }
        auto payload = bytes(data, data_size);
        if (!payload) {
            return payload.error();
        }
        return output_bytes(response, [&]() -> Result<Bytes> {
            Result<Bytes> result = Error{ErrorCode::internal, "Raw frame did not execute"};
            auto invoked =
                invoke_raw(channel, timeout_ms,
                           [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                               auto selected = require_native_framing(entry, framing);
                               if (!selected) {
                                   return selected.error();
                               }
                               clear_sessions(entry);
                               auto transaction = entry.native->begin(options);
                               if (!transaction) {
                                   return transaction.error();
                               }
                               auto exchanged = transaction.value().exchange_frame(
                                   static_cast<Byte>(command), payload.value());
                               if (!exchanged) {
                                   return exchanged.error();
                               }
                               *native_status = exchanged.value().status;
                               result = std::move(exchanged.value().data);
                               return {};
                           });
            if (!invoked) {
                return invoked.error();
            }
            return result;
        });
    });
}

/** @brief Implement the documented `df_raw_native_exchange` C ABI operation. */
int32_t df_raw_native_exchange(df_raw_channel channel, const df_native_request_v1* request,
                               uint32_t timeout_ms, uint32_t* native_status, df_buffer** response,
                               df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!request || request->struct_size != sizeof(df_native_request_v1) ||
            request->abi_version != DF_ABI_VERSION || request->command > 0xFFU ||
            request->maximum_response == 0U ||
            (request->flags & ~DF_RAW_SINGLE_CONTINUATION) != 0U || request->reserved32 != 0U ||
            !reserved_is_zero(request->reserved) || !native_status) {
            return invalid("Invalid raw native request descriptor");
        }
        auto payload = bytes(request->data, request->data_size);
        if (!payload) {
            return payload.error();
        }
        ev3::native::raw::Request core_request{
            .command = static_cast<Byte>(request->command),
            .data = Bytes(payload.value().begin(), payload.value().end()),
            .maximum_response = request->maximum_response,
            .first_frame_data_size =
                request->first_frame_data_size == DF_RAW_NO_FIRST_FRAME_BOUNDARY
                    ? std::nullopt
                    : std::optional<std::size_t>(request->first_frame_data_size),
            .single_continuation_frame = (request->flags & DF_RAW_SINGLE_CONTINUATION) != 0U,
        };
        return output_bytes(response, [&]() -> Result<Bytes> {
            Result<Bytes> result = Error{ErrorCode::internal, "Raw exchange did not execute"};
            auto invoked =
                invoke_raw(channel, timeout_ms,
                           [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                               auto selected = require_native_framing(entry, request->framing);
                               if (!selected) {
                                   return selected.error();
                               }
                               clear_sessions(entry);
                               auto exchanged = entry.native->exchange(core_request, options);
                               if (!exchanged) {
                                   return exchanged.error();
                               }
                               *native_status = exchanged.value().status;
                               result = std::move(exchanged.value().data);
                               return {};
                           });
            if (!invoked) {
                return invoked.error();
            }
            return result;
        });
    });
}

/** @brief Implement the documented `df_raw_iso_exchange` C ABI operation. */
int32_t df_raw_iso_exchange(df_raw_channel channel, const df_iso_apdu_v1* request,
                            uint32_t timeout_ms, uint32_t* iso_status, df_buffer** response,
                            df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!iso_status) {
            return invalid("ISO status output is required");
        }
        auto apdu = make_iso_apdu(request);
        if (!apdu) {
            return apdu.error();
        }
        const ev3::iso7816::raw::Limits limits{
            .max_response = request->maximum_response,
            .max_frames = request->maximum_frames,
            .correct_length = request->correct_length != 0U,
        };
        return output_bytes(response, [&]() -> Result<Bytes> {
            Result<Bytes> result = Error{ErrorCode::internal, "Raw ISO exchange did not execute"};
            auto invoked =
                invoke_raw(channel, timeout_ms,
                           [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                               if (!entry.iso) {
                                   return Error{ErrorCode::unsupported,
                                                "True ISO exchange requires ISO-wrapped transport"};
                               }
                               clear_sessions(entry);
                               auto exchanged = entry.iso->exchange(apdu.value(), options, limits);
                               if (!exchanged) {
                                   return exchanged.error();
                               }
                               *iso_status = exchanged.value().status;
                               result = std::move(exchanged.value().data);
                               return {};
                           });
            if (!invoked) {
                return invoked.error();
            }
            return result;
        });
    });
}

/** @brief Implement the documented `df_raw_authenticate_standard_aes` C ABI operation. */
int32_t df_raw_authenticate_standard_aes(df_raw_channel channel, uint32_t key_number,
                                         const uint8_t* key, size_t key_size, uint32_t timeout_ms,
                                         df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto selector = KeyNumber::make(key_number);
        if (!selector) {
            return selector.error();
        }
        auto imported = aes128_key(key, key_size);
        if (!imported) {
            return imported.error();
        }
        return invoke_raw(channel, timeout_ms,
                          [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                              if (!entry.native) {
                                  return Error{ErrorCode::unsupported,
                                               "Standard AES requires a native raw channel"};
                              }
                              clear_sessions(entry);
                              auto transaction = entry.native->begin(options);
                              if (!transaction) {
                                  return transaction.error();
                              }
                              auto material = ev3::security::standard_aes::authenticate(
                                  *entry.crypto, static_cast<Byte>(selector.value().value()),
                                  imported.value().view(), [&](Byte command, ByteView payload) {
                                      return transaction.value().exchange_frame(command, payload);
                                  });
                              if (!material) {
                                  return material.error();
                              }
                              auto session = ev3::security::standard_aes::Session::create(
                                  entry.crypto, std::move(material.value()));
                              if (!session) {
                                  return session.error();
                              }
                              entry.standard_session = std::move(session.value());
                              entry.session_generation = entry.transport->generation();
                              return {};
                          });
    });
}

/** @brief Implement the documented `df_raw_authenticate_standard_aes_provider` C ABI operation. */
int32_t df_raw_authenticate_standard_aes_provider(df_raw_channel channel, uint32_t key_number,
                                                  const df_key_provider_v1* provider,
                                                  const df_key_request_v1* request,
                                                  uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto checked =
            make_key_request(request, key_derivation::AuthenticationProfile::standard_aes,
                             key_derivation::KeyScope::native, key_number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke_raw(channel, timeout_ms,
                          [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                              if (!entry.native) {
                                  return Error{ErrorCode::unsupported,
                                               "Standard AES requires a native raw channel"};
                              }
                              clear_sessions(entry);
                              auto resolved = adapter.value()->resolve(checked.value());
                              if (!resolved) {
                                  return resolved.error();
                              }
                              auto transaction = entry.native->begin(options);
                              if (!transaction) {
                                  return transaction.error();
                              }
                              auto material = ev3::security::standard_aes::authenticate(
                                  *entry.crypto, static_cast<Byte>(key_number),
                                  resolved.value().view(), [&](Byte command, ByteView payload) {
                                      return transaction.value().exchange_frame(command, payload);
                                  });
                              if (!material) {
                                  return material.error();
                              }
                              auto session = ev3::security::standard_aes::Session::create(
                                  entry.crypto, std::move(material.value()));
                              if (!session) {
                                  return session.error();
                              }
                              entry.standard_session = std::move(session.value());
                              entry.session_generation = entry.transport->generation();
                              return {};
                          });
    });
}

/** @brief Implement the documented `df_raw_authenticate_ev2_first_aes` C ABI operation. */
int32_t df_raw_authenticate_ev2_first_aes(df_raw_channel channel, uint32_t key_number,
                                          const uint8_t* key, size_t key_size,
                                          const uint8_t* pcd_capabilities,
                                          size_t pcd_capabilities_size, uint32_t timeout_ms,
                                          df_authentication_info_v1* out, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
        }
        auto selector = KeyNumber::make(key_number);
        if (!selector) {
            return selector.error();
        }
        auto imported = aes128_key(key, key_size);
        auto capabilities = bytes(pcd_capabilities, pcd_capabilities_size);
        if (!imported || !capabilities || pcd_capabilities_size > 6U) {
            if (!imported) {
                return imported.error();
            }
            return capabilities ? invalid("PCD capabilities exceed six bytes")
                                : capabilities.error();
        }
        return invoke_raw(
            channel, timeout_ms,
            [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                if (!entry.native) {
                    return Error{ErrorCode::unsupported, "EV2 First requires a native raw channel"};
                }
                clear_sessions(entry);
                auto transaction = entry.native->begin(options);
                if (!transaction) {
                    return transaction.error();
                }
                auto material = ev3::security::ev2::authenticate_first(
                    *entry.crypto, static_cast<Byte>(selector.value().value()),
                    imported.value().view(), capabilities.value(),
                    [&](Byte command, ByteView payload) {
                        return transaction.value().exchange_frame(command, payload);
                    });
                if (!material) {
                    return material.error();
                }
                const auto information = material.value().information;
                auto session =
                    ev3::security::ev2::Session::create(entry.crypto, std::move(material.value()));
                if (!session) {
                    return session.error();
                }
                entry.ev2_session = std::move(session.value());
                entry.session_generation = entry.transport->generation();
                return write_authentication_info(out, information);
            });
    });
}

/** @brief Implement the documented `df_raw_authenticate_ev2_first_aes_provider` C ABI operation. */
int32_t df_raw_authenticate_ev2_first_aes_provider(
    df_raw_channel channel, uint32_t key_number, const df_key_provider_v1* provider,
    const df_key_request_v1* request, const uint8_t* pcd_capabilities, size_t pcd_capabilities_size,
    uint32_t timeout_ms, df_authentication_info_v1* out, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
        }
        auto capabilities = bytes(pcd_capabilities, pcd_capabilities_size);
        if (!capabilities) {
            return capabilities.error();
        }
        if (capabilities.value().size() > 6U) {
            return invalid("PCD capabilities exceed six bytes");
        }
        auto checked = make_key_request(request, key_derivation::AuthenticationProfile::ev2_first,
                                        key_derivation::KeyScope::native, key_number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke_raw(
            channel, timeout_ms,
            [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                if (!entry.native) {
                    return Error{ErrorCode::unsupported, "EV2 First requires a native raw channel"};
                }
                clear_sessions(entry);
                auto resolved = adapter.value()->resolve(checked.value());
                if (!resolved) {
                    return resolved.error();
                }
                auto transaction = entry.native->begin(options);
                if (!transaction) {
                    return transaction.error();
                }
                auto material = ev3::security::ev2::authenticate_first(
                    *entry.crypto, static_cast<Byte>(key_number), resolved.value().view(),
                    capabilities.value(), [&](Byte command, ByteView payload) {
                        return transaction.value().exchange_frame(command, payload);
                    });
                if (!material) {
                    return material.error();
                }
                const auto information = material.value().information;
                auto session =
                    ev3::security::ev2::Session::create(entry.crypto, std::move(material.value()));
                if (!session) {
                    return session.error();
                }
                entry.ev2_session = std::move(session.value());
                entry.session_generation = entry.transport->generation();
                return write_authentication_info(out, information);
            });
    });
}

/** @brief Implement the documented `df_raw_authenticate_ev2_non_first_aes` C ABI operation. */
int32_t df_raw_authenticate_ev2_non_first_aes(df_raw_channel channel, uint32_t key_number,
                                              const uint8_t* key, size_t key_size,
                                              uint32_t timeout_ms, df_authentication_info_v1* out,
                                              df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
        }
        auto selector = KeyNumber::make(key_number);
        if (!selector) {
            return selector.error();
        }
        auto imported = aes128_key(key, key_size);
        if (!imported) {
            return imported.error();
        }
        return invoke_raw(channel, timeout_ms,
                          [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                              auto current = require_current_session(entry);
                              if (!current || !entry.ev2_session) {
                                  return current ? Error{ErrorCode::session_invalid,
                                                         "EV2 NonFirst requires EV2 First"}
                                                 : current.error();
                              }
                              const auto information = entry.ev2_session->authentication();
                              const auto counter = entry.ev2_session->command_counter();
                              entry.ev2_session.reset();
                              auto transaction = entry.native->begin(options);
                              if (!transaction) {
                                  clear_sessions(entry);
                                  return transaction.error();
                              }
                              auto material = ev3::security::ev2::authenticate_nonfirst(
                                  *entry.crypto, static_cast<Byte>(selector.value().value()),
                                  imported.value().view(), information,
                                  [&](Byte command, ByteView payload) {
                                      return transaction.value().exchange_frame(command, payload);
                                  });
                              if (!material) {
                                  clear_sessions(entry);
                                  return material.error();
                              }
                              auto session = ev3::security::ev2::Session::create(
                                  entry.crypto, std::move(material.value()), counter);
                              if (!session) {
                                  clear_sessions(entry);
                                  return session.error();
                              }
                              entry.ev2_session = std::move(session.value());
                              entry.session_generation = entry.transport->generation();
                              return write_authentication_info(out, information);
                          });
    });
}

/** @brief Implement the documented `df_raw_authenticate_ev2_non_first_aes_provider` C ABI
 * operation. */
int32_t df_raw_authenticate_ev2_non_first_aes_provider(df_raw_channel channel, uint32_t key_number,
                                                       const df_key_provider_v1* provider,
                                                       const df_key_request_v1* request,
                                                       uint32_t timeout_ms,
                                                       df_authentication_info_v1* out,
                                                       df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
        }
        auto checked =
            make_key_request(request, key_derivation::AuthenticationProfile::ev2_non_first,
                             key_derivation::KeyScope::native, key_number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke_raw(
            channel, timeout_ms,
            [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                auto current = require_current_session(entry);
                if (!current) {
                    return current.error();
                }
                if (!entry.ev2_session) {
                    return Error{ErrorCode::session_invalid, "EV2 NonFirst requires EV2 First"};
                }
                const auto information = entry.ev2_session->authentication();
                const auto counter = entry.ev2_session->command_counter();
                entry.ev2_session.reset();
                auto resolved = adapter.value()->resolve(checked.value());
                if (!resolved) {
                    clear_sessions(entry);
                    return resolved.error();
                }
                auto transaction = entry.native->begin(options);
                if (!transaction) {
                    clear_sessions(entry);
                    return transaction.error();
                }
                auto material = ev3::security::ev2::authenticate_nonfirst(
                    *entry.crypto, static_cast<Byte>(key_number), resolved.value().view(),
                    information, [&](Byte command, ByteView payload) {
                        return transaction.value().exchange_frame(command, payload);
                    });
                if (!material) {
                    clear_sessions(entry);
                    return material.error();
                }
                auto session = ev3::security::ev2::Session::create(
                    entry.crypto, std::move(material.value()), counter);
                if (!session) {
                    clear_sessions(entry);
                    return session.error();
                }
                entry.ev2_session = std::move(session.value());
                entry.session_generation = entry.transport->generation();
                return write_authentication_info(out, information);
            });
    });
}

/** @brief Implement the documented `df_raw_authenticate_iso_aes` C ABI operation. */
int32_t df_raw_authenticate_iso_aes(df_raw_channel channel, uint32_t key_number,
                                    uint32_t application, const uint8_t* key, size_t key_size,
                                    uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto reference = iso_key(key_number, application);
        if (!reference) {
            return reference.error();
        }
        auto imported = aes128_key(key, key_size);
        if (!imported) {
            return imported.error();
        }
        return invoke_raw(channel, timeout_ms,
                          [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                              if (!entry.iso_checked) {
                                  return Error{ErrorCode::unsupported,
                                               "ISO AES requires an ISO raw channel"};
                              }
                              clear_sessions(entry);
                              auto session = ev3::iso7816::security::aes::authenticate(
                                  *entry.iso_checked, *entry.crypto, reference.value(),
                                  imported.value().view(), options);
                              if (!session) {
                                  return session.error();
                              }
                              entry.iso_session = std::move(session.value());
                              entry.session_generation = entry.transport->generation();
                              return {};
                          });
    });
}

/** @brief Implement the documented `df_raw_authenticate_iso_aes_provider` C ABI operation. */
int32_t df_raw_authenticate_iso_aes_provider(df_raw_channel channel, uint32_t key_number,
                                             uint32_t application,
                                             const df_key_provider_v1* provider,
                                             const df_key_request_v1* request, uint32_t timeout_ms,
                                             df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto reference = iso_key(key_number, application);
        if (!reference) {
            return reference.error();
        }
        const auto scope = application != 0U ? key_derivation::KeyScope::iso_application
                                             : key_derivation::KeyScope::iso_picc;
        auto checked = make_key_request(request, key_derivation::AuthenticationProfile::iso_aes,
                                        scope, key_number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke_raw(channel, timeout_ms,
                          [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                              if (!entry.iso_checked) {
                                  return Error{ErrorCode::unsupported,
                                               "ISO AES requires an ISO raw channel"};
                              }
                              clear_sessions(entry);
                              auto resolved = adapter.value()->resolve(checked.value());
                              if (!resolved) {
                                  return resolved.error();
                              }
                              auto session = ev3::iso7816::security::aes::authenticate(
                                  *entry.iso_checked, *entry.crypto, reference.value(),
                                  resolved.value().view(), options);
                              if (!session) {
                                  return session.error();
                              }
                              entry.iso_session = std::move(session.value());
                              entry.session_generation = entry.transport->generation();
                              return {};
                          });
    });
}

/** @brief Implement the documented `df_raw_iso_secure_exchange` C ABI operation. */
int32_t df_raw_iso_secure_exchange(df_raw_channel channel, const df_iso_apdu_v1* request,
                                   uint32_t timeout_ms, uint32_t* iso_status, df_buffer** response,
                                   df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!iso_status || (request && request->correct_length != 0U)) {
            return invalid(
                "Secure ISO exchange requires a status output and forbids length correction");
        }
        auto apdu = make_iso_apdu(request);
        if (!apdu) {
            return apdu.error();
        }
        auto command = make_checked_iso_command(apdu.value());
        if (!command) {
            return command.error();
        }
        const auto& checked_apdu = command.value().apdu();
        if (checked_apdu.cla != apdu.value().cla || checked_apdu.ins != apdu.value().ins ||
            checked_apdu.p1 != apdu.value().p1 || checked_apdu.p2 != apdu.value().p2 ||
            checked_apdu.data != apdu.value().data || checked_apdu.le != apdu.value().le ||
            checked_apdu.encoding != apdu.value().encoding) {
            return invalid("Raw ISO APDU does not exactly match its checked command form");
        }
        if (command.value().resets_authentication()) {
            return Error{ErrorCode::unsupported,
                         "Authenticated ISO exchange cannot change the selected DF"};
        }
        const ev3::iso7816::checked::Limits limits{
            .max_response = request->maximum_response,
            .max_frames = request->maximum_frames,
            .correct_read_length = false,
        };
        return output_bytes(response, [&]() -> Result<Bytes> {
            Result<Bytes> result =
                Error{ErrorCode::internal, "Secure ISO exchange did not execute"};
            auto invoked =
                invoke_raw(channel, timeout_ms,
                           [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                               auto current = require_current_session(entry);
                               if (!current) {
                                   return current.error();
                               }
                               if (!entry.iso_checked || !entry.iso_session) {
                                   return Error{ErrorCode::session_invalid,
                                                "ISO AES raw session is not active"};
                               }
                               auto exchanged =
                                   entry.iso_session->execute(*entry.iso_checked, *entry.crypto,
                                                              command.value(), options, limits);
                               if (!exchanged) {
                                   if (!entry.iso_session->valid()) {
                                       entry.iso_session.reset();
                                       entry.session_generation = 0;
                                   }
                                   return exchanged.error();
                               }
                               *iso_status = exchanged.value().status;
                               result = std::move(exchanged.value().data);
                               return {};
                           });
            if (!invoked) {
                return invoked.error();
            }
            return result;
        });
    });
}

/** @brief Implement the documented `df_raw_native_secure_exchange` C ABI operation. */
int32_t df_raw_native_secure_exchange(df_raw_channel channel,
                                      const df_native_secure_request_v1* request,
                                      uint32_t timeout_ms, df_buffer** response, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!request || request->struct_size != sizeof(df_native_secure_request_v1) ||
            request->abi_version != DF_ABI_VERSION || request->command > 0xFFU ||
            (request->profile != DF_SECURE_PROFILE_STANDARD_AES &&
             request->profile != DF_SECURE_PROFILE_EV2) ||
            request->minimum_response > request->maximum_response ||
            (request->flags & ~DF_RAW_SINGLE_CONTINUATION) != 0U ||
            request->invalidates_session > 1U || !reserved_is_zero(request->reserved)) {
            return invalid("Invalid secure-native request descriptor");
        }
        auto header = bytes(request->header, request->header_size);
        auto data = bytes(request->data, request->data_size);
        auto request_mode = mode(request->request_communication);
        auto response_mode = mode(request->response_communication);
        if (!header || !data || !request_mode || !response_mode) {
            if (!header) {
                return header.error();
            }
            if (!data) {
                return data.error();
            }
            return !request_mode ? request_mode.error() : response_mode.error();
        }
        const ev3::native::secure::Request core_request{
            .command = static_cast<Byte>(request->command),
            .header = header.value(),
            .data = data.value(),
            .request_mode = request_mode.value(),
            .response_mode = response_mode.value(),
            .minimum_response = request->minimum_response,
            .maximum_response = request->maximum_response,
            .first_frame_data_size =
                request->first_frame_data_size == DF_RAW_NO_FIRST_FRAME_BOUNDARY
                    ? std::nullopt
                    : std::optional<std::size_t>(request->first_frame_data_size),
            .single_continuation_frame = (request->flags & DF_RAW_SINGLE_CONTINUATION) != 0U,
            .invalidates_session = request->invalidates_session != 0U,
        };
        return output_bytes(response, [&]() -> Result<Bytes> {
            Result<Bytes> result = Error{ErrorCode::internal, "Secure exchange did not execute"};
            auto invoked = invoke_raw(
                channel, timeout_ms,
                [&](RawEntry& entry, const ExchangeOptions& options) -> Result<void> {
                    auto current = require_current_session(entry);
                    if (!current) {
                        return current.error();
                    }
                    if (!entry.secure) {
                        return Error{ErrorCode::unsupported,
                                     "Secure native exchange requires a native raw channel"};
                    }
                    if (request->profile == DF_SECURE_PROFILE_STANDARD_AES) {
                        if (!entry.standard_session) {
                            return Error{ErrorCode::session_invalid,
                                         "Standard AES raw session is not active"};
                        }
                        result =
                            entry.secure->exchange(core_request, *entry.standard_session, options);
                        if (!result || request->invalidates_session != 0U) {
                            entry.standard_session.reset();
                            entry.session_generation = 0;
                        }
                    } else {
                        if (!entry.ev2_session) {
                            return Error{ErrorCode::session_invalid,
                                         "EV2 raw session is not active"};
                        }
                        result = entry.secure->exchange(core_request, *entry.ev2_session, options);
                        if (!result || request->invalidates_session != 0U) {
                            entry.ev2_session.reset();
                            entry.session_generation = 0;
                        }
                    }
                    return result ? Result<void>{} : Result<void>{result.error()};
                });
            if (!invoked) {
                return invoked.error();
            }
            return result;
        });
    });
}

} // extern "C"
