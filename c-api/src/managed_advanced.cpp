/**
 * @file managed_advanced.cpp
 * @brief Delegated applications, provider key mutations, and transaction plans for C99.
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

/** @brief Implement the documented `df_create_delegated_application` C ABI operation. */
int32_t df_create_delegated_application(df_card card, uint32_t aid, uint32_t key_settings,
                                        uint32_t number_of_keys, uint32_t slot,
                                        uint32_t slot_version, uint32_t quota_limit,
                                        uint32_t iso_file_identifiers, int32_t key_settings3,
                                        int32_t iso_id, const uint8_t* df_name, size_t df_name_size,
                                        const uint8_t* encrypted_default_key,
                                        size_t encrypted_default_key_size, const uint8_t* dam_mac,
                                        size_t dam_mac_size, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto name = bytes(df_name, df_name_size);
        auto encrypted = bytes(encrypted_default_key, encrypted_default_key_size);
        auto mac = bytes(dam_mac, dam_mac_size);
        if (!name || !encrypted || !mac) {
            if (!name) {
                return name.error();
            }
            return !encrypted ? encrypted.error() : mac.error();
        }
        auto application = ApplicationId::make(aid);
        if (!application) {
            return application.error();
        }
        if (key_settings > 0xFFU || number_of_keys > 0xFFU || slot > 0xFFFFU ||
            slot_version > 0xFFU || quota_limit > 0xFFFFU || iso_file_identifiers > 1U ||
            key_settings3 < -1 || key_settings3 > 0xFF || iso_id < -1 || iso_id > 0xFFFF) {
            return invalid("Invalid delegated-application configuration");
        }
        ApplicationConfiguration application_configuration{
            .id = application.value(),
            .key_settings = static_cast<Byte>(key_settings),
            .number_of_keys = static_cast<Byte>(number_of_keys),
            .iso_file_identifiers = iso_file_identifiers != 0U,
            .key_settings3 = key_settings3 < 0
                                 ? std::nullopt
                                 : std::optional<Byte>(static_cast<Byte>(key_settings3)),
            .key_sets = {},
            .iso_id = iso_id < 0 ? std::nullopt
                                 : std::optional<std::uint16_t>(static_cast<std::uint16_t>(iso_id)),
            .df_name = Bytes(name.value().begin(), name.value().end()),
        };
        ev3::model::DelegatedApplicationConfiguration configuration{
            .application = std::move(application_configuration),
            .slot = static_cast<std::uint16_t>(slot),
            .slot_version = static_cast<Byte>(slot_version),
            .quota_limit = static_cast<std::uint16_t>(quota_limit),
        };
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.create_delegated_application(configuration, encrypted.value(), mac.value(),
                                                     options);
        });
    });
}

/** @brief Implement the documented `df_get_delegated_application_info` C ABI operation. */
int32_t df_get_delegated_application_info(df_card card, uint32_t slot, uint32_t timeout_ms,
                                          df_delegated_application_info_v1* output,
                                          df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!output || output->struct_size != sizeof(df_delegated_application_info_v1) ||
            output->abi_version != DF_ABI_VERSION || slot > 0xFFFFU ||
            !reserved_is_zero(output->reserved)) {
            return invalid("Invalid delegated-information output descriptor");
        }
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto result =
                    card.delegated_application_info(static_cast<std::uint16_t>(slot), options);
                if (!result) {
                    return result.error();
                }
                output->slot_version = result.value().slot_version;
                output->quota_limit = result.value().quota_limit;
                output->free_blocks = result.value().free_blocks;
                output->application_id = result.value().application.value();
                return {};
            });
    });
}

/** @brief Implement the documented `df_delete_delegated_application` C ABI operation. */
int32_t df_delete_delegated_application(df_card card, uint32_t aid, const uint8_t* dam_mac,
                                        size_t dam_mac_size, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto application = ApplicationId::make(aid);
        auto mac = bytes(dam_mac, dam_mac_size);
        if (!application || !mac) {
            return !application ? application.error() : mac.error();
        }
        return invoke(card, timeout_ms, [&](Card& card, const ExchangeOptions& options) {
            return card.delete_delegated_application(application.value(), mac.value(), options);
        });
    });
}

/** @brief Implement the documented `df_create_transaction_mac_file_provider` C ABI operation. */
int32_t df_create_transaction_mac_file_provider(df_card card, uint32_t file, uint32_t access_rights,
                                                const df_key_provider_v1* provider,
                                                const df_key_request_v1* request, uint32_t version,
                                                uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        auto selected_file = FileNumber::make(file);
        auto access = access_rights_from_c(access_rights);
        if (!selected_file || !access || version > 0xFFU) {
            if (!selected_file) {
                return selected_file.error();
            }
            return !access ? access.error()
                           : invalid("Transaction-MAC key version exceeds one byte");
        }
        const auto number = request ? request->key_number : 0U;
        auto checked = make_key_request(request, key_derivation::KeyPurpose::transaction_mac,
                                        key_derivation::KeyScope::native, number);
        if (!checked) {
            return checked.error();
        }
        auto adapter = KeyProviderAdapter::create(provider, request);
        if (!adapter) {
            return adapter.error();
        }
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto resolved = adapter.value()->resolve(checked.value());
                if (!resolved) {
                    return resolved.error();
                }
                return card.create_transaction_mac_file(selected_file.value(), access.value(),
                                                        resolved.value().view(),
                                                        static_cast<Byte>(version), options);
            });
    });
}

/** @brief Implement the documented `df_change_aes_key_provider` C ABI operation. */
int32_t df_change_aes_key_provider(df_card card, uint32_t number,
                                   const df_key_provider_v1* new_key_provider,
                                   const df_key_request_v1* new_key_request, uint32_t version,
                                   uint32_t authenticated_key,
                                   const df_key_provider_v1* old_key_provider,
                                   const df_key_request_v1* old_key_request, int32_t key_set,
                                   uint32_t picc_master, uint32_t timeout_ms, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (version > 0xFFU || key_set < -1 || key_set > 15 || picc_master > 1U ||
            ((old_key_provider == nullptr) != (old_key_request == nullptr))) {
            return invalid("Invalid AES key-change provider configuration");
        }
        auto target = KeyNumber::make(number);
        auto current = KeyNumber::make(authenticated_key);
        if (!target || !current) {
            return !target ? target.error() : current.error();
        }
        auto new_checked =
            make_key_request(new_key_request, key_derivation::KeyPurpose::replacement_key,
                             key_derivation::KeyScope::native, number);
        if (!new_checked) {
            return new_checked.error();
        }
        auto new_adapter = KeyProviderAdapter::create(new_key_provider, new_key_request);
        if (!new_adapter) {
            return new_adapter.error();
        }
        std::optional<key_derivation::KeyRequest> old_checked;
        std::unique_ptr<KeyProviderAdapter> old_adapter;
        if (old_key_request) {
            auto checked =
                make_key_request(old_key_request, key_derivation::KeyPurpose::current_key,
                                 key_derivation::KeyScope::native, number);
            if (!checked) {
                return checked.error();
            }
            old_checked.emplace(std::move(checked.value()));
            auto adapter = KeyProviderAdapter::create(old_key_provider, old_key_request);
            if (!adapter) {
                return adapter.error();
            }
            old_adapter = std::move(adapter.value());
        }
        return invoke(
            card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                auto replacement = new_adapter.value()->resolve(new_checked.value());
                if (!replacement) {
                    return replacement.error();
                }
                std::optional<key_derivation::Aes128Key> old_key;
                if (old_adapter) {
                    auto resolved = old_adapter->resolve(*old_checked);
                    if (!resolved) {
                        return resolved.error();
                    }
                    old_key.emplace(std::move(resolved.value()));
                }
                const ByteView old_view = old_key ? old_key->view() : ByteView{};
                const std::optional<Byte> selected_key_set =
                    key_set < 0 ? std::nullopt : std::optional<Byte>(static_cast<Byte>(key_set));
                return card.change_aes_key(target.value(), replacement.value().view(),
                                           static_cast<Byte>(version), current.value(), old_view,
                                           selected_key_set, picc_master != 0U, options);
            });
    });
}

/** @brief Implement the documented `df_execute_transaction` C ABI operation. */
int32_t df_execute_transaction(df_card card, const df_transaction_operation_v1* operations,
                               size_t operation_count, uint32_t return_mac, uint32_t timeout_ms,
                               df_buffer** output, df_error* error) {
    return boundary(error, [&]() -> Result<void> {
        if (!operations || operation_count == 0U || operation_count > 128U || return_mac > 1U) {
            return invalid("Transaction requires one through 128 operations");
        }
        ev3::managed::TransactionPlan plan;
        for (std::size_t index = 0; index < operation_count; ++index) {
            const auto& input = operations[index];
            if (input.struct_size != sizeof(df_transaction_operation_v1) ||
                input.abi_version != DF_ABI_VERSION || !reserved_is_zero(input.reserved)) {
                return invalid("Invalid transaction operation descriptor");
            }
            auto file = FileNumber::make(input.file);
            auto selected_mode = mode(input.communication);
            auto offset = Offset::make(input.offset);
            auto record = Offset::make(input.record);
            auto data = bytes(input.data, input.data_size);
            if (!file || !selected_mode || !offset || !record || !data) {
                if (!file) {
                    return file.error();
                }
                if (!selected_mode) {
                    return selected_mode.error();
                }
                if (!offset) {
                    return offset.error();
                }
                return !record ? record.error() : data.error();
            }
            Result<commands::Command> command = invalid("Unknown transaction operation kind");
            switch (input.kind) {
            case DF_TRANSACTION_WRITE_DATA:
                if (input.amount != 0U || input.record != 0U) {
                    return invalid("Write-data transaction has unexpected scalar fields");
                }
                command = commands::write_data(file.value(), offset.value(), data.value(),
                                               selected_mode.value());
                break;
            case DF_TRANSACTION_CREDIT:
                if (input.offset != 0U || input.record != 0U || input.data_size != 0U) {
                    return invalid("Credit transaction has unexpected data fields");
                }
                command = commands::credit(file.value(), input.amount, selected_mode.value());
                break;
            case DF_TRANSACTION_DEBIT:
                if (input.offset != 0U || input.record != 0U || input.data_size != 0U) {
                    return invalid("Debit transaction has unexpected data fields");
                }
                command = commands::debit(file.value(), input.amount, selected_mode.value());
                break;
            case DF_TRANSACTION_LIMITED_CREDIT:
                if (input.offset != 0U || input.record != 0U || input.data_size != 0U) {
                    return invalid("Limited-credit transaction has unexpected data fields");
                }
                command =
                    commands::limited_credit(file.value(), input.amount, selected_mode.value());
                break;
            case DF_TRANSACTION_WRITE_RECORD:
                if (input.amount != 0U || input.record != 0U) {
                    return invalid("Write-record transaction has unexpected scalar fields");
                }
                command = commands::write_record(file.value(), offset.value(), data.value(),
                                                 selected_mode.value());
                break;
            case DF_TRANSACTION_UPDATE_RECORD:
                if (input.amount != 0U) {
                    return invalid("Update-record transaction has an unexpected amount");
                }
                command = commands::update_record(file.value(), record.value(), offset.value(),
                                                  data.value(), selected_mode.value());
                break;
            case DF_TRANSACTION_CLEAR_RECORD_FILE:
                if (input.amount != 0U || input.offset != 0U || input.record != 0U ||
                    input.data_size != 0U) {
                    return invalid("Clear-record transaction has unexpected fields");
                }
                command = commands::clear_record_file(file.value());
                break;
            default:
                break;
            }
            if (!command) {
                return command.error();
            }
            auto added = plan.add(std::move(command.value()));
            if (!added) {
                return added.error();
            }
        }
        return output_bytes(output, [&]() -> Result<Bytes> {
            Result<Bytes> result = Error{ErrorCode::internal, "Transaction did not execute"};
            auto invoked = invoke(
                card, timeout_ms, [&](Card& card, const ExchangeOptions& options) -> Result<void> {
                    result = card.execute_transaction(plan, return_mac != 0U, options);
                    if (!result) {
                        return result.error();
                    }
                    return {};
                });
            if (!invoked) {
                return invoked.error();
            }
            return result;
        });
    });
}

} // extern "C"
