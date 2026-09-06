/**
 * @file native.cpp
 * @brief Managed native checked commands and distinct AES authentication entrypoints.
 */
#include "detail/internal.hpp"

using namespace desfire;
using namespace desfire::c_api::detail;

extern "C" {
/** @brief Implement the documented `df_get_version` C ABI operation. */
int32_t df_get_version(df_card card, uint32_t timeout_ms, df_buffer** out, df_error* error) {
    return boundary(error, [&] {
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return output_bytes(out, [&]() -> Result<Bytes> {
                auto result = card.get_version(options);
                if (!result) {
                    return result.error();
                }
                const auto& v = result.value();
                Bytes data;
                data.reserve(28);
                for (const auto& p : {v.hardware, v.software}) {
                    append(data, std::array<Byte, 7>{p.vendor, p.type, p.subtype, p.major, p.minor,
                                                     p.storage, p.protocol});
                }
                append(data, v.uid);
                append(data, v.batch);
                data.push_back(v.production_week);
                data.push_back(v.production_year);
                return data;
            });
        });
    });
}

/** @brief Implement the documented `df_free_memory` C ABI operation. */
int32_t df_free_memory(df_card card, uint32_t timeout_ms, uint32_t* out, df_error* error) {
    return boundary(error, [&] {
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (!out) {
                              return invalid("Output is required");
                          }
                          auto result = card.free_memory(options);
                          if (!result) {
                              return result.error();
                          }
                          *out = result.value();
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_select_application` C ABI operation. */
int32_t df_select_application(df_card card, uint32_t aid, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto id = ApplicationId::make(aid);
                          if (!id) {
                              return id.error();
                          }
                          return card.select_application(id.value(), options);
                      });
    });
}

/** @brief Implement the documented `df_file_ids` C ABI operation. */
int32_t df_file_ids(df_card card, uint32_t timeout_ms, df_buffer** out, df_error* error) {
    return boundary(error, [&] {
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return output_bytes(out, [&]() -> Result<Bytes> {
                auto result = card.file_ids(options);
                if (!result) {
                    return result.error();
                }
                Bytes data;
                data.reserve(result.value().size());
                for (auto file : result.value()) {
                    data.push_back(static_cast<Byte>(file.value()));
                }
                return data;
            });
        });
    });
}

/** @brief Implement the documented `df_authenticate_standard_aes` C ABI operation. */
int32_t df_authenticate_standard_aes(df_card card, uint32_t key_number, const uint8_t* key,
                                     size_t key_size, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto selector = KeyNumber::make(key_number);
        if (!selector) {
            return selector.error();
        }
        auto imported = aes128_key(key, key_size);
        if (!imported) {
            return imported.error();
        }
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          return card.authenticate_standard_aes(
                              selector.value(), std::move(imported.value()), options);
                      });
    });
}

/** @brief Implement the documented `df_authenticate_standard_aes_provider` C ABI operation. */
int32_t df_authenticate_standard_aes_provider(df_card card, uint32_t key_number,
                                              const df_key_provider_v1* provider,
                                              const df_key_request_v1* request, uint32_t timeout_ms,
                                              df_error* error) {
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
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                return card.authenticate_standard_aes(*adapter.value(), checked.value(), options);
            });
    });
}

/** @brief Implement the documented `df_authenticate_ev2_first_aes` C ABI operation. */
int32_t df_authenticate_ev2_first_aes(df_card card, uint32_t key_number, const uint8_t* key,
                                      size_t key_size, uint32_t timeout_ms,
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
        if (!imported) {
            return imported.error();
        }
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto result = card.authenticate_ev2_first_aes(
                              selector.value(), std::move(imported.value()), options);
                          if (!result) {
                              return result.error();
                          }
                          return write_authentication_info(out, result.value());
                      });
    });
}

/** @brief Implement the documented `df_authenticate_ev2_first_aes_provider` C ABI operation. */
int32_t df_authenticate_ev2_first_aes_provider(df_card card, uint32_t key_number,
                                               const df_key_provider_v1* provider,
                                               const df_key_request_v1* request,
                                               uint32_t timeout_ms, df_authentication_info_v1* out,
                                               df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
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
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto result =
                    card.authenticate_ev2_first_aes(*adapter.value(), checked.value(), options);
                if (!result) {
                    return result.error();
                }
                return write_authentication_info(out, result.value());
            });
    });
}

/** @brief Implement the documented `df_authenticate_ev2_first_aes_with_capabilities` C ABI
 * operation. */
int32_t df_authenticate_ev2_first_aes_with_capabilities(
    df_card card, uint32_t key_number, const uint8_t* key, size_t key_size,
    const uint8_t* pcd_capabilities, size_t pcd_capabilities_size, uint32_t timeout_ms,
    df_authentication_info_v1* out, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
        }
        auto capabilities = bytes(pcd_capabilities, pcd_capabilities_size);
        if (!capabilities || pcd_capabilities_size > 6U) {
            return capabilities ? invalid("PCD capabilities exceed six bytes")
                                : capabilities.error();
        }
        auto selector = KeyNumber::make(key_number);
        if (!selector) {
            return selector.error();
        }
        auto imported = aes128_key(key, key_size);
        if (!imported) {
            return imported.error();
        }
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto result = card.authenticate_ev2_first_aes_with_capabilities(
                    selector.value(), std::move(imported.value()), capabilities.value(), options);
                if (!result) {
                    return result.error();
                }
                return write_authentication_info(out, result.value());
            });
    });
}

/** @brief Implement the documented `df_authenticate_ev2_first_aes_with_capabilities_provider` C ABI
 * operation. */
int32_t df_authenticate_ev2_first_aes_with_capabilities_provider(
    df_card card, uint32_t key_number, const df_key_provider_v1* provider,
    const df_key_request_v1* request, const uint8_t* pcd_capabilities, size_t pcd_capabilities_size,
    uint32_t timeout_ms, df_authentication_info_v1* out, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto output_check = write_authentication_info(out, {});
        if (!output_check) {
            return output_check.error();
        }
        auto capabilities = bytes(pcd_capabilities, pcd_capabilities_size);
        if (!capabilities || pcd_capabilities_size > 6U) {
            return capabilities ? invalid("PCD capabilities exceed six bytes")
                                : capabilities.error();
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
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto result = card.authenticate_ev2_first_aes_with_capabilities(
                              *adapter.value(), checked.value(), capabilities.value(), options);
                          if (!result) {
                              return result.error();
                          }
                          return write_authentication_info(out, result.value());
                      });
    });
}

/** @brief Implement the documented `df_authenticate_ev2_non_first_aes` C ABI operation. */
int32_t df_authenticate_ev2_non_first_aes(df_card card, uint32_t key_number, const uint8_t* key,
                                          size_t key_size, uint32_t timeout_ms,
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
        if (!imported) {
            return imported.error();
        }
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto result = card.authenticate_ev2_non_first_aes(
                              selector.value(), std::move(imported.value()), options);
                          if (!result) {
                              return result.error();
                          }
                          return write_authentication_info(out, result.value());
                      });
    });
}

/** @brief Implement the documented `df_authenticate_ev2_non_first_aes_provider` C ABI operation. */
int32_t df_authenticate_ev2_non_first_aes_provider(df_card card, uint32_t key_number,
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
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto result =
                    card.authenticate_ev2_non_first_aes(*adapter.value(), checked.value(), options);
                if (!result) {
                    return result.error();
                }
                return write_authentication_info(out, result.value());
            });
    });
}

/** @brief Implement the documented `df_application_ids` C ABI operation. */
int32_t df_application_ids(df_card handle, uint32_t timeout_ms, df_buffer** output,
                           df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto command = commands::get_application_ids();
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_iso_file_ids` C ABI operation. */
int32_t df_iso_file_ids(df_card handle, uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto command = commands::get_iso_file_ids();
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_get_key_settings` C ABI operation. */
int32_t df_get_key_settings(df_card handle, uint32_t timeout_ms, df_buffer** output,
                            df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto command = commands::get_key_settings();
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_get_key_set_versions` C ABI operation. */
int32_t df_get_key_set_versions(df_card handle, uint32_t timeout_ms, df_buffer** output,
                                df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto command = commands::get_key_set_versions();
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_get_card_uid` C ABI operation. */
int32_t df_get_card_uid(df_card handle, uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto command = commands::get_card_uid();
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_read_originality_signature` C ABI operation. */
int32_t df_read_originality_signature(df_card handle, uint32_t timeout_ms, df_buffer** output,
                                      df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto command = commands::read_originality_signature();
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_abort_transaction` C ABI operation. */
int32_t df_abort_transaction(df_card handle, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto command = commands::abort_transaction();
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_format_picc` C ABI operation. */
int32_t df_format_picc(df_card handle, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto command = commands::format_picc();
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_delete_file` C ABI operation. */
int32_t df_delete_file(df_card handle, uint32_t file, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto command = commands::delete_file(f.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_get_file_settings` C ABI operation. */
int32_t df_get_file_settings(df_card handle, uint32_t file, uint32_t timeout_ms, df_buffer** output,
                             df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto command = commands::get_file_settings(f.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_clear_record_file` C ABI operation. */
int32_t df_clear_record_file(df_card handle, uint32_t file, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto command = commands::clear_record_file(f.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_get_file_counters` C ABI operation. */
int32_t df_get_file_counters(df_card handle, uint32_t file, uint32_t communication,
                             uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto m = mode(communication);
                if (!m) {
                    return m.error();
                }
                auto command = commands::get_file_counters(f.value(), m.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_delete_application` C ABI operation. */
int32_t df_delete_application(df_card handle, uint32_t aid, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto a = ApplicationId::make(aid);
                          if (!a) {
                              return a.error();
                          }
                          auto command = commands::delete_application(a.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_change_key_settings` C ABI operation. */
int32_t df_change_key_settings(df_card handle, uint32_t settings, uint32_t timeout_ms,
                               df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (settings > 255) {
                              return invalid("Key settings exceed one byte");
                          }
                          auto command = commands::change_key_settings(static_cast<Byte>(settings));
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_get_key_version` C ABI operation. */
int32_t df_get_key_version(df_card handle, uint32_t number, int32_t key_set, uint32_t timeout_ms,
                           df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto k = KeyNumber::make(number);
                if (!k) {
                    return k.error();
                }
                if (key_set < -1 || key_set > 255) {
                    return invalid("Invalid key set");
                }
                std::optional<Byte> ks;
                if (key_set >= 0) {
                    ks = static_cast<Byte>(key_set);
                }
                auto command = commands::get_key_version(k.value(), ks);
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_initialize_key_set` C ABI operation. */
int32_t df_initialize_key_set(df_card handle, uint32_t key_set, uint32_t timeout_ms,
                              df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (key_set > 255) {
                              return invalid("Invalid key set");
                          }
                          auto command = commands::initialize_key_set(static_cast<Byte>(key_set));
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_roll_key_set` C ABI operation. */
int32_t df_roll_key_set(df_card handle, uint32_t key_set, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (key_set > 255) {
                              return invalid("Invalid key set");
                          }
                          auto command = commands::roll_key_set(static_cast<Byte>(key_set));
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_finalize_key_set` C ABI operation. */
int32_t df_finalize_key_set(df_card handle, uint32_t key_set, uint32_t version, uint32_t timeout_ms,
                            df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (key_set > 255 || version > 255) {
                              return invalid("Invalid key set/version");
                          }
                          auto command = commands::finalize_key_set(static_cast<Byte>(key_set),
                                                                    static_cast<Byte>(version));
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_read_data` C ABI operation. */
int32_t df_read_data(df_card handle, uint32_t file, uint32_t offset, uint32_t length,
                     uint32_t communication, uint32_t timeout_ms, df_buffer** output,
                     df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto m = mode(communication);
                if (!m) {
                    return m.error();
                }
                auto o = Offset::make(offset);
                if (!o) {
                    return o.error();
                }
                auto n = ByteCount::make(length);
                if (!n) {
                    return n.error();
                }
                auto command = commands::read_data(f.value(), o.value(), n.value(), m.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_write_data` C ABI operation. */
int32_t df_write_data(df_card handle, uint32_t file, uint32_t offset, const uint8_t* data,
                      size_t size, uint32_t communication, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto m = mode(communication);
                if (!m) {
                    return m.error();
                }
                auto o = Offset::make(offset);
                if (!o) {
                    return o.error();
                }
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                auto command = commands::write_data(f.value(), o.value(), d.value(), m.value());
                if (!command) {
                    return command.error();
                }
                auto response = card.execute(command.value(), options);
                if (!response) {
                    return response.error();
                }
                return {};
            });
    });
}

/** @brief Implement the documented `df_write_record` C ABI operation. */
int32_t df_write_record(df_card handle, uint32_t file, uint32_t offset, const uint8_t* data,
                        size_t size, uint32_t communication, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto m = mode(communication);
                if (!m) {
                    return m.error();
                }
                auto o = Offset::make(offset);
                if (!o) {
                    return o.error();
                }
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                auto command = commands::write_record(f.value(), o.value(), d.value(), m.value());
                if (!command) {
                    return command.error();
                }
                auto response = card.execute(command.value(), options);
                if (!response) {
                    return response.error();
                }
                return {};
            });
    });
}

/** @brief Implement the documented `df_read_records` C ABI operation. */
int32_t df_read_records(df_card handle, uint32_t file, uint32_t first, uint32_t count,
                        uint32_t communication, uint32_t timeout_ms, df_buffer** output,
                        df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto m = mode(communication);
                if (!m) {
                    return m.error();
                }
                auto o = Offset::make(first);
                if (!o) {
                    return o.error();
                }
                auto n = ByteCount::make(count);
                if (!n) {
                    return n.error();
                }
                auto command = commands::read_records(f.value(), o.value(), n.value(), m.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_update_record` C ABI operation. */
int32_t df_update_record(df_card handle, uint32_t file, uint32_t record, uint32_t offset,
                         const uint8_t* data, size_t size, uint32_t communication,
                         uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto f = FileNumber::make(file);
                if (!f) {
                    return f.error();
                }
                auto m = mode(communication);
                if (!m) {
                    return m.error();
                }
                auto r = Offset::make(record);
                if (!r) {
                    return r.error();
                }
                auto o = Offset::make(offset);
                if (!o) {
                    return o.error();
                }
                auto d = bytes(data, size);
                if (!d) {
                    return d.error();
                }
                auto command =
                    commands::update_record(f.value(), r.value(), o.value(), d.value(), m.value());
                if (!command) {
                    return command.error();
                }
                auto response = card.execute(command.value(), options);
                if (!response) {
                    return response.error();
                }
                return {};
            });
    });
}

/** @brief Implement the documented `df_credit` C ABI operation. */
int32_t df_credit(df_card handle, uint32_t file, uint32_t amount, uint32_t communication,
                  uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto command = commands::credit(f.value(), amount, m.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_debit` C ABI operation. */
int32_t df_debit(df_card handle, uint32_t file, uint32_t amount, uint32_t communication,
                 uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto command = commands::debit(f.value(), amount, m.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_limited_credit` C ABI operation. */
int32_t df_limited_credit(df_card handle, uint32_t file, uint32_t amount, uint32_t communication,
                          uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto command = commands::limited_credit(f.value(), amount, m.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_get_value` C ABI operation. */
int32_t df_get_value(df_card handle, uint32_t file, uint32_t communication, uint32_t timeout_ms,
                     int32_t* output, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          if (!output) {
                              return invalid("Output is required");
                          }
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto command = commands::get_value(f.value(), m.value());
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          auto value = commands::parse_value(response.value());
                          if (!value) {
                              return value.error();
                          }
                          *output = value.value();
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_commit_transaction` C ABI operation. */
int32_t df_commit_transaction(df_card handle, uint32_t return_mac, uint32_t timeout_ms,
                              df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                if (return_mac > 1) {
                    return invalid("Return MAC must be boolean");
                }
                auto command = commands::commit_transaction(return_mac != 0);
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_commit_reader_id` C ABI operation. */
int32_t df_commit_reader_id(df_card handle, const uint8_t* reader_id, size_t size,
                            uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto d = bytes(reader_id, size);
                if (!d) {
                    return d.error();
                }
                auto command = commands::commit_reader_id(d.value());
                if (!command) {
                    return command.error();
                }
                return output_bytes(output, [&] { return card.execute(command.value(), options); });
            });
    });
}

/** @brief Implement the documented `df_create_application` C ABI operation. */
int32_t df_create_application(df_card handle, uint32_t aid, uint32_t key_settings,
                              uint32_t key_count, int32_t iso_id, const uint8_t* df_name,
                              size_t df_name_size, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto a = ApplicationId::make(aid);
                if (!a) {
                    return a.error();
                }
                if (key_settings > 255 || key_count > 255 || iso_id < -1 || iso_id > 65535) {
                    return invalid("Invalid application configuration");
                }
                auto n = bytes(df_name, df_name_size);
                if (!n) {
                    return n.error();
                }
                ApplicationConfiguration config{a.value()};
                config.key_settings = static_cast<Byte>(key_settings);
                config.number_of_keys = static_cast<Byte>(key_count);
                if (iso_id >= 0) {
                    config.iso_file_identifiers = true;
                    config.iso_id = static_cast<uint16_t>(iso_id);
                }
                config.df_name = Bytes(n.value().begin(), n.value().end());
                auto command = commands::create_application(config);
                if (!command) {
                    return command.error();
                }
                auto response = card.execute(command.value(), options);
                if (!response) {
                    return response.error();
                }
                return {};
            });
    });
}

/** @brief Implement the documented `df_create_data_file` C ABI operation. */
int32_t df_create_data_file(df_card handle, uint32_t file, uint32_t length, uint32_t communication,
                            uint32_t access_rights, int32_t iso_id, uint32_t backup,
                            uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto access = access_rights_from_c(access_rights);
                          if (!access) {
                              return access.error();
                          }
                          auto n = ByteCount::make(length);
                          if (!n) {
                              return n.error();
                          }
                          if (iso_id < -1 || iso_id > 65535 || backup > 1) {
                              return invalid("Invalid data file configuration");
                          }
                          DataFileConfiguration config{f.value(), n.value()};
                          config.communication = m.value();
                          config.access = access.value();
                          config.backup = backup != 0;
                          if (iso_id >= 0) {
                              config.iso_id = static_cast<uint16_t>(iso_id);
                          }
                          auto command = commands::create_data_file(config);
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_create_value_file` C ABI operation. */
int32_t df_create_value_file(df_card handle, uint32_t file, int32_t lower_limit,
                             int32_t upper_limit, int32_t initial_value, uint32_t communication,
                             uint32_t access_rights, uint32_t limited_credit,
                             uint32_t free_get_value, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto access = access_rights_from_c(access_rights);
                          if (!access) {
                              return access.error();
                          }
                          if (limited_credit > 1 || free_get_value > 1) {
                              return invalid("Flags must be boolean");
                          }
                          ValueFileConfiguration config{f.value()};
                          config.lower_limit = lower_limit;
                          config.upper_limit = upper_limit;
                          config.initial_value = initial_value;
                          config.communication = m.value();
                          config.access = access.value();
                          config.limited_credit_enabled = limited_credit != 0;
                          config.free_get_value = free_get_value != 0;
                          auto command = commands::create_value_file(config);
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_create_record_file` C ABI operation. */
int32_t df_create_record_file(df_card handle, uint32_t file, uint32_t record_size,
                              uint32_t maximum_records, uint32_t communication,
                              uint32_t access_rights, int32_t iso_id, uint32_t cyclic,
                              uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto access = access_rights_from_c(access_rights);
                          if (!access) {
                              return access.error();
                          }
                          auto n = ByteCount::make(record_size);
                          if (!n) {
                              return n.error();
                          }
                          auto count = ByteCount::make(maximum_records);
                          if (!count) {
                              return count.error();
                          }
                          if (iso_id < -1 || iso_id > 65535 || cyclic > 1) {
                              return invalid("Invalid record configuration");
                          }
                          RecordFileConfiguration config{f.value(), n.value(), count.value()};
                          config.communication = m.value();
                          config.access = access.value();
                          config.cyclic = cyclic != 0;
                          if (iso_id >= 0) {
                              config.iso_id = static_cast<uint16_t>(iso_id);
                          }
                          auto command = commands::create_record_file(config);
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_change_file_settings` C ABI operation. */
int32_t df_change_file_settings(df_card handle, uint32_t file, uint32_t communication,
                                uint32_t access_rights, uint32_t command_communication,
                                uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto m = mode(communication);
                          if (!m) {
                              return m.error();
                          }
                          auto access = access_rights_from_c(access_rights);
                          if (!access) {
                              return access.error();
                          }
                          auto policy = mode(command_communication);
                          if (!policy) {
                              return policy.error();
                          }
                          FileSettingsChange config{f.value()};
                          config.communication = m.value();
                          config.access = access.value();
                          config.command_communication = policy.value();
                          auto command = commands::change_file_settings(config);
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_create_transaction_mac_file` C ABI operation. */
int32_t df_create_transaction_mac_file(df_card handle, uint32_t file, uint32_t access_rights,
                                       const uint8_t* key, size_t key_size, uint32_t version,
                                       uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(handle, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto f = FileNumber::make(file);
                          if (!f) {
                              return f.error();
                          }
                          auto access = access_rights_from_c(access_rights);
                          if (!access) {
                              return access.error();
                          }
                          auto k = bytes(key, key_size);
                          if (!k) {
                              return k.error();
                          }
                          if (version > 255) {
                              return invalid("Invalid key version");
                          }
                          auto command = commands::create_transaction_mac_file(
                              f.value(), access.value(), k.value(), static_cast<Byte>(version));
                          if (!command) {
                              return command.error();
                          }
                          auto response = card.execute(command.value(), options);
                          if (!response) {
                              return response.error();
                          }
                          return {};
                      });
    });
}

/** @brief Implement the documented `df_change_aes_key` C ABI operation. */
int32_t df_change_aes_key(df_card handle, uint32_t number, const uint8_t* new_key,
                          size_t new_key_size, uint32_t version, uint32_t authenticated_key,
                          const uint8_t* old_key, size_t old_key_size, int32_t key_set,
                          uint32_t picc_master, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&] {
        return invoke(
            handle, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto k = KeyNumber::make(number);
                if (!k) {
                    return k.error();
                }
                auto current = KeyNumber::make(authenticated_key);
                if (!current) {
                    return current.error();
                }
                auto n = bytes(new_key, new_key_size);
                if (!n) {
                    return n.error();
                }
                auto old = bytes(old_key, old_key_size);
                if (!old) {
                    return old.error();
                }
                if (version > 255 || key_set < -1 || key_set > 255 || picc_master > 1) {
                    return invalid("Invalid key configuration");
                }
                std::optional<Byte> ks;
                if (key_set >= 0) {
                    ks = static_cast<Byte>(key_set);
                }
                auto command =
                    commands::change_aes_key(k.value(), n.value(), static_cast<Byte>(version),
                                             current.value(), old.value(), ks, picc_master != 0);
                if (!command) {
                    return command.error();
                }
                auto response = card.execute(command.value(), options);
                if (!response) {
                    return response.error();
                }
                return {};
            });
    });
}

} // extern "C"
