/**
 * @file iso.cpp
 * @brief Managed checked ISO/IEC 7816 commands and AES authentication.
 */
#include "detail/internal.hpp"

using namespace desfire;
using namespace desfire::c_api::detail;

extern "C" {
/** @brief Implement the documented `df_iso_select_file` C ABI operation. */
int32_t df_iso_select_file(df_card handle, uint32_t identifier, uint32_t selection,
                           uint32_t response, uint32_t timeout_ms, df_buffer** output,
                           df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (selection > 2 || (response != 0 && response != 12)) {
                              return invalid("Invalid ISO selection");
                          }
                          auto command = iso7816::Command::select_file(
                              identifier, static_cast<iso7816::FileSelection>(selection),
                              static_cast<iso7816::SelectionResponse>(response));
                          if (!command) {
                              return command.error();
                          }
                          return output_bytes(output, [&]() -> Result<Bytes> {
                              auto response = card.iso_command(command.value(), options);
                              if (!response) {
                                  return response.error();
                              }
                              if (!response.value().success()) {
                                  return Error{ErrorCode::card_rejected, "ISO command rejected",
                                               Outcome::rejected, response.value().status};
                              }
                              return std::move(response.value().data);
                          });
                      });
    });
}

/** @brief Implement the documented `df_iso_select_df_name` C ABI operation. */
int32_t df_iso_select_df_name(df_card handle, const uint8_t* name, size_t size, uint32_t response,
                              uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto data = bytes(name, size);
                          if (!data) {
                              return data.error();
                          }
                          if (response != 0 && response != 12) {
                              return invalid("Invalid ISO selection response");
                          }
                          auto command = iso7816::Command::select_df_name(
                              data.value(), static_cast<iso7816::SelectionResponse>(response));
                          if (!command) {
                              return command.error();
                          }
                          return output_bytes(output, [&]() -> Result<Bytes> {
                              auto response = card.iso_command(command.value(), options);
                              if (!response) {
                                  return response.error();
                              }
                              if (!response.value().success()) {
                                  return Error{ErrorCode::card_rejected, "ISO command rejected",
                                               Outcome::rejected, response.value().status};
                              }
                              return std::move(response.value().data);
                          });
                      });
    });
}

/** @brief Implement the documented `df_iso_read_binary` C ABI operation. */
int32_t df_iso_read_binary(df_card handle, int32_t short_identifier, uint32_t offset,
                           uint32_t length, uint32_t timeout_ms, df_buffer** output,
                           df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto address = short_identifier < 0
                                             ? iso7816::BinaryAddress::current_file(offset)
                                             : iso7816::BinaryAddress::short_file(
                                                   static_cast<uint32_t>(short_identifier), offset);
                          if (short_identifier < -1) {
                              return invalid("Invalid ISO short identifier");
                          }
                          if (!address) {
                              return address.error();
                          }
                          auto command = iso7816::Command::read_binary(address.value(), length);
                          if (!command) {
                              return command.error();
                          }
                          return output_bytes(output, [&]() -> Result<Bytes> {
                              auto response = card.iso_command(command.value(), options);
                              if (!response) {
                                  return response.error();
                              }
                              if (!response.value().success()) {
                                  return Error{ErrorCode::card_rejected, "ISO command rejected",
                                               Outcome::rejected, response.value().status};
                              }
                              return std::move(response.value().data);
                          });
                      });
    });
}

/** @brief Implement the documented `df_iso_update_binary` C ABI operation. */
int32_t df_iso_update_binary(df_card handle, int32_t short_identifier, uint32_t offset,
                             const uint8_t* data, size_t size, uint32_t timeout_ms,
                             df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto address = short_identifier < 0
                                   ? iso7816::BinaryAddress::current_file(offset)
                                   : iso7816::BinaryAddress::short_file(
                                         static_cast<uint32_t>(short_identifier), offset);
                if (short_identifier < -1) {
                    return invalid("Invalid ISO short identifier");
                }
                if (!address) {
                    return address.error();
                }
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                auto command = iso7816::Command::update_binary(address.value(), d.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&]() -> Result<Bytes> {
                    auto response = card.iso_command(command.value(), options);
                    if (!response) {
                        return response.error();
                    }
                    if (!response.value().success()) {
                        return Error{ErrorCode::card_rejected, "ISO command rejected",
                                     Outcome::rejected, response.value().status};
                    }
                    return std::move(response.value().data);
                });
            });
    });
}

/** @brief Implement the documented `df_iso_read_records` C ABI operation. */
int32_t df_iso_read_records(df_card handle, uint32_t record, uint32_t short_identifier,
                            uint32_t selection, uint32_t length, uint32_t timeout_ms,
                            df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (selection != 4 && selection != 5) {
                              return invalid("Invalid record selector");
                          }
                          auto command = iso7816::Command::read_records(
                              record, short_identifier,
                              static_cast<iso7816::RecordSelection>(selection), length);
                          if (!command) {
                              return command.error();
                          }
                          return output_bytes(output, [&]() -> Result<Bytes> {
                              auto response = card.iso_command(command.value(), options);
                              if (!response) {
                                  return response.error();
                              }
                              if (!response.value().success()) {
                                  return Error{ErrorCode::card_rejected, "ISO command rejected",
                                               Outcome::rejected, response.value().status};
                              }
                              return std::move(response.value().data);
                          });
                      });
    });
}

/** @brief Implement the documented `df_iso_append_record` C ABI operation. */
int32_t df_iso_append_record(df_card handle, uint32_t short_identifier, const uint8_t* data,
                             size_t size, uint32_t timeout_ms, df_buffer** output,
                             df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                auto command = iso7816::Command::append_record(short_identifier, d.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&]() -> Result<Bytes> {
                    auto response = card.iso_command(command.value(), options);
                    if (!response) {
                        return response.error();
                    }
                    if (!response.value().success()) {
                        return Error{ErrorCode::card_rejected, "ISO command rejected",
                                     Outcome::rejected, response.value().status};
                    }
                    return std::move(response.value().data);
                });
            });
    });
}

/** @brief Implement the documented `df_iso_get_challenge` C ABI operation. */
int32_t df_iso_get_challenge(df_card handle, uint32_t length, uint32_t timeout_ms,
                             df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto command = iso7816::Command::get_challenge(length);
                          if (!command) {
                              return command.error();
                          }
                          return output_bytes(output, [&]() -> Result<Bytes> {
                              auto response = card.iso_command(command.value(), options);
                              if (!response) {
                                  return response.error();
                              }
                              if (!response.value().success()) {
                                  return Error{ErrorCode::card_rejected, "ISO command rejected",
                                               Outcome::rejected, response.value().status};
                              }
                              return std::move(response.value().data);
                          });
                      });
    });
}

/** @brief Implement the documented `df_iso_external_authenticate` C ABI operation. */
int32_t df_iso_external_authenticate(df_card handle, uint32_t number, uint32_t application,
                                     uint32_t algorithm, const uint8_t* data, size_t size,
                                     uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto k = iso_key(number, application);
                if (!k) {
                    return k.error();
                }
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                if (algorithm != 0 && algorithm != 2 && algorithm != 4 && algorithm != 9) {
                    return invalid("Invalid ISO algorithm");
                }
                auto command = iso7816::Command::external_authenticate(
                    static_cast<iso7816::Algorithm>(algorithm), k.value(), d.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&]() -> Result<Bytes> {
                    auto response = card.iso_command(command.value(), options);
                    if (!response) {
                        return response.error();
                    }
                    if (!response.value().success()) {
                        return Error{ErrorCode::card_rejected, "ISO command rejected",
                                     Outcome::rejected, response.value().status};
                    }
                    return std::move(response.value().data);
                });
            });
    });
}

/** @brief Implement the documented `df_iso_internal_authenticate` C ABI operation. */
int32_t df_iso_internal_authenticate(df_card handle, uint32_t number, uint32_t application,
                                     uint32_t algorithm, const uint8_t* data, size_t size,
                                     uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto k = iso_key(number, application);
                if (!k) {
                    return k.error();
                }
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                if (algorithm != 0 && algorithm != 2 && algorithm != 4 && algorithm != 9) {
                    return invalid("Invalid ISO algorithm");
                }
                auto command = iso7816::Command::internal_authenticate(
                    static_cast<iso7816::Algorithm>(algorithm), k.value(), d.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&]() -> Result<Bytes> {
                    auto response = card.iso_command(command.value(), options);
                    if (!response) {
                        return response.error();
                    }
                    if (!response.value().success()) {
                        return Error{ErrorCode::card_rejected, "ISO command rejected",
                                     Outcome::rejected, response.value().status};
                    }
                    return std::move(response.value().data);
                });
            });
    });
}

/** @brief Implement the documented `df_authenticate_iso_aes` C ABI operation. */
int32_t df_authenticate_iso_aes(df_card handle, uint32_t number, uint32_t application,
                                const uint8_t* key, size_t key_size, uint32_t timeout_ms,
                                df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto k = iso_key(number, application);
                if (!k) {
                    return k.error();
                }
                auto imported = aes128_key(key, key_size);
                if (!imported) {
                    return imported.error();
                }
                return card.authenticate_iso_aes(k.value(), std::move(imported.value()), options);
            });
    });
}

/** @brief Implement the documented `df_authenticate_iso_aes_provider` C ABI operation. */
int32_t df_authenticate_iso_aes_provider(df_card handle, uint32_t number, uint32_t application,
                                         const df_key_provider_v1* provider,
                                         const df_key_request_v1* request, uint32_t timeout_ms,
                                         df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto key_reference = iso_key(number, application);
        if (!key_reference) {
            return key_reference.error();
        }
        const auto scope = application != 0U ? key_derivation::KeyScope::iso_application
                                             : key_derivation::KeyScope::iso_picc;
        auto checked = make_key_request(request, key_derivation::AuthenticationProfile::iso_aes,
                                        scope, number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          return card.authenticate_iso_aes(key_reference.value(), *adapter.value(),
                                                           checked.value(), options);
                      });
    });
}

/** @brief Implement the documented `df_iso_update_record` C ABI operation. */
int32_t df_iso_update_record(df_card card, uint32_t instruction, uint32_t record,
                             uint32_t short_identifier, uint32_t reference_control,
                             const uint8_t* data, size_t data_size, uint32_t timeout_ms,
                             df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (instruction != DF_ISO_UPDATE_RECORD_DC && instruction != DF_ISO_UPDATE_RECORD_DD) {
            return invalid("ISO UPDATE RECORD instruction must be 0xDC or 0xDD");
        }
        auto payload = bytes(data, data_size);
        if (!payload) {
            return payload.error();
        }
        auto command = iso7816::Command::update_record(
            static_cast<iso7816::UpdateRecordInstruction>(instruction), record, short_identifier,
            reference_control, payload.value());
        if (!command) {
            return command.error();
        }
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                return output_bytes(output, [&]() -> Result<Bytes> {
                    auto response = card.iso_command(command.value(), options);
                    if (!response) {
                        return response.error();
                    }
                    if (!response.value().success()) {
                        return Error{ErrorCode::card_rejected, "ISO UPDATE RECORD rejected",
                                     Outcome::rejected, response.value().status};
                    }
                    return std::move(response.value().data);
                });
            });
    });
}
} // extern "C"
