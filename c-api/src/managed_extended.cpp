/**
 * @file managed_extended.cpp
 * @brief Checked EV3 operations added after the original C ABI surface.
 */
#include "detail/internal.hpp"

using namespace desfire;
using namespace desfire::c_api::detail;

namespace {
    /**
     * @brief Report whether every descriptor-reserved word remains zero.
     * @tparam Size Compile-time number of reserved words.
     * @param reserved Fixed reserved-word array to inspect.
     * @return True only when every reserved word is zero.
     */
    template <std::size_t Size>
    bool reserved_is_zero(const std::uint64_t (&reserved)[Size]) noexcept {
        return std::all_of(std::begin(reserved), std::end(reserved),
                           [](std::uint64_t value) { return value == 0; });
    }
} // namespace

extern "C" {

/** @brief Implement the documented `df_get_df_names` C ABI operation. */
int32_t df_get_df_names(df_card card, uint32_t timeout_ms, df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          return output_bytes(output, [&]() -> Result<Bytes> {
                              auto records = card.df_names(options);
                              if (!records) {
                                  return records.error();
                              }
                              Bytes encoded;
                              for (const auto& record : records.value()) {
                                  const auto aid = record.application.value();
                                  encoded.push_back(static_cast<Byte>(aid));
                                  encoded.push_back(static_cast<Byte>(aid >> 8U));
                                  encoded.push_back(static_cast<Byte>(aid >> 16U));
                                  encoded.push_back(static_cast<Byte>(record.iso_id >> 8U));
                                  encoded.push_back(static_cast<Byte>(record.iso_id));
                                  encoded.push_back(static_cast<Byte>(record.name.size()));
                                  append(encoded, record.name);
                              }
                              return encoded;
                          });
                      });
    });
}

/** @brief Implement the documented `df_reset_authentication` C ABI operation. */
int32_t df_reset_authentication(df_card card, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        return invoke(card, 5000U, [](Card& card, const ExchangeOptions&) {
            return card.reset_authentication();
        });
    });
}

/** @brief Implement the documented `df_restore_transfer` C ABI operation. */
int32_t df_restore_transfer(df_card card, uint32_t target_file, uint32_t source_file,
                            uint32_t communication, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto target = FileNumber::make(target_file);
        auto source = FileNumber::make(source_file);
        auto selected_mode = mode(communication);
        if (!target || !source || !selected_mode) {
            if (!target) {
                return target.error();
            }
            return !source ? source.error() : selected_mode.error();
        }
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.restore_transfer(target.value(), source.value(), selected_mode.value(),
                                         options);
        });
    });
}

/** @brief Implement the documented `df_get_card_uid_variant` C ABI operation. */
int32_t df_get_card_uid_variant(df_card card, uint32_t option, uint32_t timeout_ms,
                                df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (option > DF_UID_WITH_NUID) {
            return invalid("Unknown UID request option");
        }
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                return output_bytes(output, [&]() -> Result<Bytes> {
                    auto result =
                        card.card_uid(static_cast<commands::CardUidRequest>(option), options);
                    if (!result) {
                        return result.error();
                    }
                    Bytes data = std::move(result.value().uid);
                    if (result.value().nuid) {
                        append(data, *result.value().nuid);
                    }
                    return data;
                });
            });
    });
}

/** @brief Implement the documented `df_set_picc_configuration` C ABI operation. */
int32_t df_set_picc_configuration(df_card card, const df_picc_configuration_v1* configuration,
                                  uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!configuration || configuration->struct_size != sizeof(df_picc_configuration_v1) ||
            configuration->abi_version != DF_ABI_VERSION || configuration->disable_format > 1U ||
            configuration->random_identifier > 1U ||
            configuration->proximity_check_mandatory > 1U ||
            configuration->virtual_card_authentication_mandatory > 1U ||
            configuration->error_code_binding > 1U ||
            configuration->random_identifier_configuration > 1U ||
            configuration->four_byte_nuid_configuration > 1U ||
            !reserved_is_zero(configuration->reserved)) {
            return invalid("Invalid PICC configuration descriptor");
        }
        const ev3::model::PiccConfiguration checked_configuration{
            .disable_format = configuration->disable_format != 0U,
            .random_identifier = configuration->random_identifier != 0U,
            .proximity_check_mandatory = configuration->proximity_check_mandatory != 0U,
            .virtual_card_authentication_mandatory =
                configuration->virtual_card_authentication_mandatory != 0U,
            .error_code_binding = configuration->error_code_binding != 0U,
            .random_identifier_configuration = configuration->random_identifier_configuration != 0U,
            .four_byte_nuid_configuration = configuration->four_byte_nuid_configuration != 0U,
        };
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.set_picc_configuration(checked_configuration, options);
        });
    });
}

/** @brief Implement the documented `df_set_capability_configuration` C ABI operation. */
int32_t df_set_capability_configuration(df_card card, const uint8_t* capabilities,
                                        size_t capabilities_size, uint32_t timeout_ms,
                                        df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto data = bytes(capabilities, capabilities_size);
        if (!data) {
            return data.error();
        }
        if (data.value().size() != 9U) {
            return invalid("Capability configuration must contain nine bytes");
        }
        ev3::model::CapabilityConfiguration configuration;
        std::copy(data.value().begin(), data.value().end(), configuration.data.begin());
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.set_capability_configuration(configuration, options);
        });
    });
}

/** @brief Implement the documented `df_set_default_aes_key` C ABI operation. */
int32_t df_set_default_aes_key(df_card card, const uint8_t* key, size_t key_size,
                               uint32_t key_version, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto material = bytes(key, key_size);
        if (!material) {
            return material.error();
        }
        if (material.value().size() != 16U || key_version > 0xFFU) {
            return invalid("Default AES key requires sixteen bytes and one version byte");
        }
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.set_default_aes_key(material.value(), static_cast<Byte>(key_version),
                                            options);
        });
    });
}

/** @brief Implement the documented `df_set_default_aes_key_provider` C ABI operation. */
int32_t df_set_default_aes_key_provider(df_card card, const df_key_provider_v1* provider,
                                        const df_key_request_v1* request, uint32_t key_version,
                                        uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (key_version > 0xFFU) {
            return invalid("Default AES key version exceeds one byte");
        }
        const auto number = request ? request->key_number : 0U;
        auto checked = make_key_request(request, key_derivation::KeyPurpose::replacement_key,
                                        key_derivation::KeyScope::native, number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke(card, timeout_ms,
                      [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                          auto resolved = adapter.value()->resolve(checked.value());
                          if (!resolved) {
                              return resolved.error();
                          }
                          return card.set_default_aes_key(resolved.value().view(),
                                                          static_cast<Byte>(key_version), options);
                      });
    });
}

/** @brief Implement the documented `df_set_ats` C ABI operation. */
int32_t df_set_ats(df_card card, const uint8_t* ats, size_t ats_size, uint32_t timeout_ms,
                   df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto data = bytes(ats, ats_size);
        if (!data) {
            return data.error();
        }
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.set_ats(data.value(), options);
        });
    });
}

/** @brief Implement the documented `df_set_atqa` C ABI operation. */
int32_t df_set_atqa(df_card card, uint32_t atqa, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (atqa > 0xFFFFU) {
            return invalid("ATQA exceeds sixteen bits");
        }
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.set_atqa(static_cast<std::uint16_t>(atqa), options);
        });
    });
}

} // extern "C"
