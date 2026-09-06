/** @file entrypoints.cpp
 * @brief JNI entry points for managed, raw, authentication, and lifecycle calls.
 */
#include "context.hpp"
#include "key_provider.hpp"
#include "transport.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

namespace desfire::jni {
    namespace {
        /** @brief Copy one bounded Java array into wiping native storage. */
        InputBytes copy_input(JNIEnv* env, jbyteArray input, std::size_t maximum) {
            if (!input) {
                throw std::invalid_argument("null byte array");
            }
            const auto size = static_cast<std::size_t>(env->GetArrayLength(input));
            if (size > maximum) {
                throw std::invalid_argument("byte array size");
            }
            InputBytes result(size);
            env->GetByteArrayRegion(input, 0, static_cast<jsize>(size),
                                    reinterpret_cast<jbyte*>(result.bytes.data()));
            if (env->ExceptionCheck()) {
                throw std::invalid_argument("byte array copy");
            }
            return result;
        }

        /** @brief Narrow a positive Kotlin timeout to the C ABI. */
        std::uint32_t timeout_value(jlong timeout) {
            if (timeout <= 0 || static_cast<std::uint64_t>(timeout) > UINT32_MAX) {
                throw std::invalid_argument("timeout");
            }
            return static_cast<std::uint32_t>(timeout);
        }

        /** @brief Narrow a non-negative Kotlin Long to size_t. */
        std::size_t size_value(jlong value) {
            if (value < 0 ||
                static_cast<std::uint64_t>(value) >
                    static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                throw std::invalid_argument("size");
            }
            return static_cast<std::size_t>(value);
        }

        /** @brief Initialize the versioned EV2 authentication output descriptor. */
        df_authentication_info_v1 authentication_info() {
            df_authentication_info_v1 result{};
            result.struct_size = sizeof(result);
            result.abi_version = DF_ABI_VERSION;
            return result;
        }

        /** @brief Encode only public EV2 metadata into the fixed Kotlin result. */
        std::vector<std::uint8_t> encode(const df_authentication_info_v1& information) {
            std::vector<std::uint8_t> result;
            result.reserve(16U);
            result.insert(result.end(), std::begin(information.transaction_identifier),
                          std::end(information.transaction_identifier));
            result.insert(result.end(), std::begin(information.picc_capabilities),
                          std::end(information.picc_capabilities));
            result.insert(result.end(), std::begin(information.pcd_capabilities),
                          std::end(information.pcd_capabilities));
            return result;
        }

        /** @brief Dispatch one managed direct-key authentication profile. */
        std::int32_t authenticate_managed_direct(df_card handle, jint profile, jint key_number,
                                                 jboolean application, const InputBytes& key,
                                                 const InputBytes& pcd_capabilities,
                                                 std::uint32_t timeout,
                                                 std::vector<std::uint8_t>& result,
                                                 df_error* error) {
            if (key_number < 0 || application > 1 || profile < 0 || profile > 3) {
                throw std::invalid_argument("authentication selector");
            }
            auto information = authentication_info();
            std::int32_t status{};
            switch (profile) {
            case DF_AUTH_PROFILE_STANDARD_AES:
                status =
                    df_authenticate_standard_aes(handle, static_cast<std::uint32_t>(key_number),
                                                 key.data(), key.size(), timeout, error);
                break;
            case DF_AUTH_PROFILE_EV2_FIRST:
                status = df_authenticate_ev2_first_aes_with_capabilities(
                    handle, static_cast<std::uint32_t>(key_number), key.data(), key.size(),
                    pcd_capabilities.data(), pcd_capabilities.size(), timeout, &information, error);
                break;
            case DF_AUTH_PROFILE_EV2_NON_FIRST:
                status = df_authenticate_ev2_non_first_aes(
                    handle, static_cast<std::uint32_t>(key_number), key.data(), key.size(), timeout,
                    &information, error);
                break;
            case DF_AUTH_PROFILE_ISO_AES:
                status = df_authenticate_iso_aes(handle, static_cast<std::uint32_t>(key_number),
                                                 application ? 1U : 0U, key.data(), key.size(),
                                                 timeout, error);
                break;
            default:
                throw std::invalid_argument("authentication profile");
            }
            if (status == DF_OK && (profile == DF_AUTH_PROFILE_EV2_FIRST ||
                                    profile == DF_AUTH_PROFILE_EV2_NON_FIRST)) {
                result = encode(information);
            }
            return status;
        }

        /** @brief Dispatch one managed provider-key authentication profile. */
        std::int32_t
        authenticate_managed_provider(df_card handle, jint profile, jint key_number,
                                      jboolean application, ProviderArguments& provider,
                                      const InputBytes& pcd_capabilities, std::uint32_t timeout,
                                      std::vector<std::uint8_t>& result, df_error* error) {
            if (key_number < 0 || application > 1 || profile < 0 || profile > 3) {
                throw std::invalid_argument("authentication selector");
            }
            auto information = authentication_info();
            std::int32_t status{};
            switch (profile) {
            case DF_AUTH_PROFILE_STANDARD_AES:
                status = df_authenticate_standard_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), &provider.provider,
                    &provider.request, timeout, error);
                break;
            case DF_AUTH_PROFILE_EV2_FIRST:
                status = df_authenticate_ev2_first_aes_with_capabilities_provider(
                    handle, static_cast<std::uint32_t>(key_number), &provider.provider,
                    &provider.request, pcd_capabilities.data(), pcd_capabilities.size(), timeout,
                    &information, error);
                break;
            case DF_AUTH_PROFILE_EV2_NON_FIRST:
                status = df_authenticate_ev2_non_first_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), &provider.provider,
                    &provider.request, timeout, &information, error);
                break;
            case DF_AUTH_PROFILE_ISO_AES:
                status = df_authenticate_iso_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), application ? 1U : 0U,
                    &provider.provider, &provider.request, timeout, error);
                break;
            default:
                throw std::invalid_argument("authentication profile");
            }
            if (status == DF_OK && (profile == DF_AUTH_PROFILE_EV2_FIRST ||
                                    profile == DF_AUTH_PROFILE_EV2_NON_FIRST)) {
                result = encode(information);
            }
            return status;
        }

        /** @brief Dispatch one raw direct-key authentication profile. */
        std::int32_t authenticate_raw_direct(df_raw_channel handle, jint profile, jint key_number,
                                             jboolean application, const InputBytes& key,
                                             const InputBytes& pcd_capabilities,
                                             std::uint32_t timeout,
                                             std::vector<std::uint8_t>& result, df_error* error) {
            if (key_number < 0 || application > 1 || profile < 0 || profile > 3) {
                throw std::invalid_argument("raw authentication selector");
            }
            auto information = authentication_info();
            std::int32_t status{};
            switch (profile) {
            case DF_AUTH_PROFILE_STANDARD_AES:
                status =
                    df_raw_authenticate_standard_aes(handle, static_cast<std::uint32_t>(key_number),
                                                     key.data(), key.size(), timeout, error);
                break;
            case DF_AUTH_PROFILE_EV2_FIRST:
                status = df_raw_authenticate_ev2_first_aes(
                    handle, static_cast<std::uint32_t>(key_number), key.data(), key.size(),
                    pcd_capabilities.data(), pcd_capabilities.size(), timeout, &information, error);
                break;
            case DF_AUTH_PROFILE_EV2_NON_FIRST:
                status = df_raw_authenticate_ev2_non_first_aes(
                    handle, static_cast<std::uint32_t>(key_number), key.data(), key.size(), timeout,
                    &information, error);
                break;
            case DF_AUTH_PROFILE_ISO_AES:
                status = df_raw_authenticate_iso_aes(handle, static_cast<std::uint32_t>(key_number),
                                                     application ? 1U : 0U, key.data(), key.size(),
                                                     timeout, error);
                break;
            default:
                throw std::invalid_argument("raw authentication profile");
            }
            if (status == DF_OK && (profile == DF_AUTH_PROFILE_EV2_FIRST ||
                                    profile == DF_AUTH_PROFILE_EV2_NON_FIRST)) {
                result = encode(information);
            }
            return status;
        }

        /** @brief Dispatch one raw provider-key authentication profile. */
        std::int32_t authenticate_raw_provider(df_raw_channel handle, jint profile, jint key_number,
                                               jboolean application, ProviderArguments& provider,
                                               const InputBytes& pcd_capabilities,
                                               std::uint32_t timeout,
                                               std::vector<std::uint8_t>& result, df_error* error) {
            if (key_number < 0 || application > 1 || profile < 0 || profile > 3) {
                throw std::invalid_argument("raw authentication selector");
            }
            auto information = authentication_info();
            std::int32_t status{};
            switch (profile) {
            case DF_AUTH_PROFILE_STANDARD_AES:
                status = df_raw_authenticate_standard_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), &provider.provider,
                    &provider.request, timeout, error);
                break;
            case DF_AUTH_PROFILE_EV2_FIRST:
                status = df_raw_authenticate_ev2_first_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), &provider.provider,
                    &provider.request, pcd_capabilities.data(), pcd_capabilities.size(), timeout,
                    &information, error);
                break;
            case DF_AUTH_PROFILE_EV2_NON_FIRST:
                status = df_raw_authenticate_ev2_non_first_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), &provider.provider,
                    &provider.request, timeout, &information, error);
                break;
            case DF_AUTH_PROFILE_ISO_AES:
                status = df_raw_authenticate_iso_aes_provider(
                    handle, static_cast<std::uint32_t>(key_number), application ? 1U : 0U,
                    &provider.provider, &provider.request, timeout, error);
                break;
            default:
                throw std::invalid_argument("raw authentication profile");
            }
            if (status == DF_OK && (profile == DF_AUTH_PROFILE_EV2_FIRST ||
                                    profile == DF_AUTH_PROFILE_EV2_NON_FIRST)) {
                result = encode(information);
            }
            return status;
        }

        /** @brief Prefix a raw status as little-endian uint32 before response bytes. */
        std::vector<std::uint8_t> raw_result(std::uint32_t status, const df_buffer* output) {
            const auto size = df_buffer_size(output);
            std::vector<std::uint8_t> result;
            result.reserve(4U + size);
            result.push_back(static_cast<std::uint8_t>(status));
            result.push_back(static_cast<std::uint8_t>(status >> 8U));
            result.push_back(static_cast<std::uint8_t>(status >> 16U));
            result.push_back(static_cast<std::uint8_t>(status >> 24U));
            const auto* bytes = df_buffer_data(output);
            if (size != 0U) {
                result.insert(result.end(), bytes, bytes + size);
            }
            return result;
        }

        /** @brief Derive exactly one AES-128 key and transfer it into wiping storage. */
        InputBytes derive_key(const InputBytes& master, const InputBytes& diversification,
                              df_error* error) {
            df_buffer* raw_output = nullptr;
            const auto status =
                df_offline_derive_nxp_aes128(master.data(), master.size(), diversification.data(),
                                             diversification.size(), &raw_output, error);
            std::unique_ptr<df_buffer, decltype(&df_buffer_free)> output(raw_output,
                                                                         df_buffer_free);
            if (status != DF_OK) {
                throw std::runtime_error("key derivation failed");
            }
            if (!output || df_buffer_size(output.get()) != 16U) {
                set_error(error, DF_INTERNAL, DF_NOT_SENT,
                          "Offline derivation returned an invalid key");
                throw std::runtime_error("key derivation output");
            }
            InputBytes key(16U);
            std::copy_n(df_buffer_data(output.get()), key.size(), key.bytes.data());
            return key;
        }

        /** @brief Append one C uint32 scalar in the private little-endian JNI format. */
        void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
            output.push_back(static_cast<std::uint8_t>(value));
            output.push_back(static_cast<std::uint8_t>(value >> 8U));
            output.push_back(static_cast<std::uint8_t>(value >> 16U));
            output.push_back(static_cast<std::uint8_t>(value >> 24U));
        }

        /** @brief Read one uint32 from the private transaction-plan representation. */
        std::uint32_t read_u32(const InputBytes& input, std::size_t& offset) {
            if (offset > input.size() || input.size() - offset < 4U) {
                throw std::invalid_argument("transaction plan field");
            }
            const auto* data = input.data() + offset;
            offset += 4U;
            return static_cast<std::uint32_t>(data[0]) |
                   (static_cast<std::uint32_t>(data[1]) << 8U) |
                   (static_cast<std::uint32_t>(data[2]) << 16U) |
                   (static_cast<std::uint32_t>(data[3]) << 24U);
        }

        /** @brief C descriptors and owned write bytes for one decoded transaction plan. */
        struct TransactionInputs final {
            std::vector<df_transaction_operation_v1> operations;
            std::vector<std::vector<std::uint8_t>> data;
        };

        /** @brief Decode a bounded pointer-free Kotlin transaction plan into C descriptors. */
        TransactionInputs decode_transaction_plan(const InputBytes& input) {
            std::size_t offset{};
            const auto count = read_u32(input, offset);
            if (count == 0U || count > 128U) {
                throw std::invalid_argument("transaction plan count");
            }
            TransactionInputs result;
            result.operations.reserve(count);
            result.data.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                const auto kind = read_u32(input, offset);
                const auto file = read_u32(input, offset);
                const auto communication = read_u32(input, offset);
                const auto operation_offset = read_u32(input, offset);
                const auto record = read_u32(input, offset);
                const auto amount = read_u32(input, offset);
                const auto data_size = static_cast<std::size_t>(read_u32(input, offset));
                if (offset > input.size() || data_size > input.size() - offset) {
                    throw std::invalid_argument("transaction plan data");
                }
                result.data.emplace_back(input.data() + offset, input.data() + offset + data_size);
                offset += data_size;

                df_transaction_operation_v1 operation{};
                operation.struct_size = sizeof(operation);
                operation.abi_version = DF_ABI_VERSION;
                operation.kind = kind;
                operation.file = file;
                operation.communication = communication;
                operation.offset = operation_offset;
                operation.record = record;
                operation.amount = amount;
                operation.data = result.data.back().data();
                operation.data_size = result.data.back().size();
                result.operations.push_back(operation);
            }
            if (offset != input.size()) {
                throw std::invalid_argument("transaction plan trailing data");
            }
            return result;
        }

        /** @brief Build one versioned delegated configuration from private JNI scalars. */
        df_delegated_application_configuration_v1
        delegated_configuration(const std::vector<jlong>& numbers, const InputBytes& df_name) {
            require_counts(numbers.size(), 14U, 1U, 1U);
            for (std::size_t index : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 9U, 10U, 11U, 12U, 13U}) {
                require_unsigned(numbers[index]);
            }
            require_signed(numbers[7]);
            require_signed(numbers[8]);
            df_delegated_application_configuration_v1 configuration{};
            configuration.struct_size = sizeof(configuration);
            configuration.abi_version = DF_ABI_VERSION;
            configuration.application_id = static_cast<std::uint32_t>(numbers[0]);
            configuration.key_settings = static_cast<std::uint32_t>(numbers[1]);
            configuration.number_of_keys = static_cast<std::uint32_t>(numbers[2]);
            configuration.slot = static_cast<std::uint32_t>(numbers[3]);
            configuration.slot_version = static_cast<std::uint32_t>(numbers[4]);
            configuration.quota_limit = static_cast<std::uint32_t>(numbers[5]);
            configuration.iso_file_identifiers = static_cast<std::uint32_t>(numbers[6]);
            configuration.key_settings3 = static_cast<std::int32_t>(numbers[7]);
            configuration.iso_id = static_cast<std::int32_t>(numbers[8]);
            configuration.df_name = df_name.data();
            configuration.df_name_size = df_name.size();
            configuration.has_key_sets = static_cast<std::uint32_t>(numbers[9]);
            configuration.active_key_set_version = static_cast<std::uint32_t>(numbers[10]);
            configuration.number_of_key_sets = static_cast<std::uint32_t>(numbers[11]);
            configuration.maximum_key_size = static_cast<std::uint32_t>(numbers[12]);
            configuration.key_set_settings = static_cast<std::uint32_t>(numbers[13]);
            return configuration;
        }
    } // namespace
} // namespace desfire::jni

using namespace desfire::jni;

extern "C" {
/** @brief Return the linked C ABI version for Kotlin package verification. */
JNIEXPORT jint JNICALL Java_com_desfire_ev3_NativeRuntime_abiVersion(JNIEnv*, jclass) {
    return static_cast<jint>(df_abi_version());
}

/** @brief Return the linked manifest digest for Kotlin package verification. */
JNIEXPORT jstring JNICALL Java_com_desfire_ev3_NativeRuntime_manifestSha256(JNIEnv* env, jclass) {
    return env->NewStringUTF(df_manifest_sha256());
}

/** @brief Open one managed handle after validating every Java callback. */
JNIEXPORT jlong JNICALL Java_com_desfire_ev3_Native_open(JNIEnv* env, jclass, jobject transport,
                                                         jint framing, jint max_transmit,
                                                         jint max_receive, jint max_native_frame) {
    df_error error{};
    df_card handle{};
    try {
        auto context = make_transport_context(env, transport);
        auto descriptor = make_transport_descriptor(*context, framing, max_transmit, max_receive,
                                                    max_native_frame);
        if (df_open(&descriptor, &handle, &error) != DF_OK) {
            throw_error(env, error);
            return 0;
        }
        try {
            insert_managed(handle, std::move(context));
        } catch (...) {
            df_error ignored{};
            df_close(handle, &ignored);
            throw;
        }
        return static_cast<jlong>(handle);
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid JNI transport arguments");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Cannot create JNI card connection");
    }
    throw_error(env, error);
    return 0;
}

/** @brief Close a managed handle only after C close succeeds. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_close(JNIEnv* env, jclass, jlong raw_handle) {
    df_error error{};
    try {
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        if (df_close(handle, &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        erase_managed(handle);
        return;
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "JNI card close failed");
    }
    throw_error(env, error);
}

/** @brief Request provider and transport cancellation outside the managed FIFO gate. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_cancel(JNIEnv* env, jclass, jlong raw_handle) {
    df_error error{};
    try {
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        context->cancel_provider();
        if (df_cancel(handle, &error) != DF_OK) {
            throw_error(env, error);
        }
        return;
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "JNI card cancellation failed");
    }
    throw_error(env, error);
}

/** @brief Execute one generated managed operation and release its C buffer exactly once. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_Native_invoke(JNIEnv* env, jclass,
                                                                jlong raw_handle, jint operation,
                                                                jlongArray numeric_input,
                                                                jobjectArray data_input) {
    df_error error{};
    df_buffer* output = nullptr;
    bool dispatched = false;
    try {
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        auto arguments = read_arguments(env, numeric_input, data_input);
        auto& numbers = arguments.numbers;
        auto& blobs = arguments.blobs;
        std::int32_t status = DF_INVALID_ARGUMENT;
        std::vector<std::uint8_t> scalar_result;
        dispatched = true;
        switch (operation) {
#include "operations.inc"
        default:
            throw std::invalid_argument("operation");
        }
        if (status != DF_OK) {
            df_buffer_free(output);
            output = nullptr;
            throw_error(env, error);
            return nullptr;
        }
        return take_output(env, output, scalar_result);
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid JNI operation arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, dispatched ? DF_UNKNOWN : DF_NOT_SENT,
                  "JNI operation failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}

/** @brief Authenticate a managed handle with one copied direct AES-128 key. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_Native_authenticateDirect(
    JNIEnv* env, jclass, jlong raw_handle, jint profile, jint key_number, jboolean application,
    jbyteArray key_input, jbyteArray capabilities_input, jlong timeout_input) {
    df_error error{};
    try {
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        const auto key = copy_input(env, key_input, 16U);
        const auto capabilities = copy_input(env, capabilities_input, 6U);
        std::vector<std::uint8_t> result;
        if (authenticate_managed_direct(handle, profile, key_number, application, key, capabilities,
                                        timeout_value(timeout_input), result, &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return to_java_bytes(env, result.data(), result.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid managed authentication arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Managed authentication bridge failed");
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Derive an AES-128 key in wiping native storage before managed authentication. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_Native_authenticateDerived(
    JNIEnv* env, jclass, jlong raw_handle, jint profile, jint key_number, jboolean application,
    jbyteArray master_input, jbyteArray diversification_input, jbyteArray capabilities_input,
    jlong timeout_input) {
    df_error error{};
    try {
        const auto master = copy_input(env, master_input, 16U);
        const auto diversification = copy_input(env, diversification_input, 31U);
        auto key = derive_key(master, diversification, &error);
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        const auto capabilities = copy_input(env, capabilities_input, 6U);
        std::vector<std::uint8_t> result;
        if (authenticate_managed_direct(handle, profile, key_number, application, key, capabilities,
                                        timeout_value(timeout_input), result, &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return to_java_bytes(env, result.data(), result.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid derived authentication arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        if (error.code == DF_OK) {
            set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Derived authentication bridge failed");
        }
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Resolve one scoped provider key before managed card I/O. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_Native_authenticateProvider(
    JNIEnv* env, jclass, jlong raw_handle, jint profile, jint scope, jint key_number,
    jboolean application, jobject bridge, jbyteArray reference, jbyteArray diversification,
    jbyteArray user_context, jint application_id, jint key_set, jbyteArray capabilities_input,
    jlong timeout_input) {
    df_error error{};
    try {
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        ProviderArguments provider(env, bridge, DF_KEY_PURPOSE_AUTHENTICATION, profile, scope,
                                   key_number, application_id, key_set, reference, diversification,
                                   user_context);
        ActiveProvider active(context, provider.context);
        const auto capabilities = copy_input(env, capabilities_input, 6U);
        std::vector<std::uint8_t> result;
        if (authenticate_managed_provider(handle, profile, key_number, application, provider,
                                          capabilities, timeout_value(timeout_input), result,
                                          &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return to_java_bytes(env, result.data(), result.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid provider authentication arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Provider authentication bridge failed");
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Open an independent raw handle with separate callback ownership. */
JNIEXPORT jlong JNICALL Java_com_desfire_ev3_raw_RawNative_open(JNIEnv* env, jclass,
                                                                jobject transport, jint framing,
                                                                jint max_transmit, jint max_receive,
                                                                jint max_native_frame) {
    df_error error{};
    df_raw_channel handle{};
    try {
        auto context = make_transport_context(env, transport);
        auto descriptor = make_transport_descriptor(*context, framing, max_transmit, max_receive,
                                                    max_native_frame);
        if (df_raw_open(&descriptor, &handle, &error) != DF_OK) {
            throw_error(env, error);
            return 0;
        }
        try {
            insert_raw(handle, std::move(context));
        } catch (...) {
            df_error ignored{};
            df_raw_close(handle, &ignored);
            throw;
        }
        return static_cast<jlong>(handle);
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid raw transport arguments");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Cannot create JNI raw channel");
    }
    throw_error(env, error);
    return 0;
}

/** @brief Close a raw handle only after C close succeeds. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_raw_RawNative_close(JNIEnv* env, jclass,
                                                                jlong raw_handle) {
    df_error error{};
    try {
        const auto handle = static_cast<df_raw_channel>(raw_handle);
        const auto context = retain_raw(handle);
        if (df_raw_close(handle, &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        erase_raw(handle);
        return;
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI raw handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "JNI raw close failed");
    }
    throw_error(env, error);
}

/** @brief Request provider and transport cancellation outside the raw FIFO gate. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_raw_RawNative_cancel(JNIEnv* env, jclass,
                                                                 jlong raw_handle) {
    df_error error{};
    try {
        const auto handle = static_cast<df_raw_channel>(raw_handle);
        const auto context = retain_raw(handle);
        context->cancel_provider();
        if (df_raw_cancel(handle, &error) != DF_OK) {
            throw_error(env, error);
        }
        return;
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI raw handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "JNI raw cancellation failed");
    }
    throw_error(env, error);
}

/** @brief Execute one raw request descriptor and return an owned byte result. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_raw_RawNative_invoke(JNIEnv* env, jclass,
                                                                       jlong raw_handle,
                                                                       jint operation,
                                                                       jlongArray numeric_input,
                                                                       jobjectArray data_input) {
    df_error error{};
    df_buffer* output = nullptr;
    try {
        const auto handle = static_cast<df_raw_channel>(raw_handle);
        const auto context = retain_raw(handle);
        auto arguments = read_arguments(env, numeric_input, data_input);
        const auto& numbers = arguments.numbers;
        const auto& blobs = arguments.blobs;
        std::uint32_t response_status{};
        std::int32_t status{};
        switch (operation) {
        case 0:
            require_counts(numbers.size(), 0U, blobs.size(), 0U);
            status = df_raw_reset(handle, &error);
            break;
        case 1:
            require_counts(numbers.size(), 0U, blobs.size(), 0U);
            status = df_raw_notify_state_change(handle, &error);
            break;
        case 2:
            require_counts(numbers.size(), 3U, blobs.size(), 1U);
            require_unsigned(numbers[0]);
            require_unsigned(numbers[1]);
            status = df_raw_native_frame(handle, static_cast<std::uint32_t>(numbers[0]),
                                         static_cast<std::uint32_t>(numbers[1]), blobs[0].data(),
                                         blobs[0].size(), timeout_value(numbers[2]),
                                         &response_status, &output, &error);
            break;
        case 3: {
            require_counts(numbers.size(), 6U, blobs.size(), 1U);
            require_unsigned(numbers[0]);
            require_unsigned(numbers[1]);
            require_unsigned(numbers[4]);
            df_native_request_v1 request{};
            request.struct_size = sizeof(request);
            request.abi_version = DF_ABI_VERSION;
            request.framing = static_cast<std::uint32_t>(numbers[0]);
            request.command = static_cast<std::uint32_t>(numbers[1]);
            request.data = blobs[0].data();
            request.data_size = blobs[0].size();
            request.maximum_response = size_value(numbers[2]);
            request.first_frame_data_size =
                numbers[3] == -1 ? DF_RAW_NO_FIRST_FRAME_BOUNDARY : size_value(numbers[3]);
            request.flags = numbers[4] != 0 ? DF_RAW_SINGLE_CONTINUATION : 0U;
            status = df_raw_native_exchange(handle, &request, timeout_value(numbers[5]),
                                            &response_status, &output, &error);
            break;
        }
        case 4:
        case 6: {
            require_counts(numbers.size(), 11U, blobs.size(), 1U);
            for (std::size_t index = 0; index < 10U; ++index) {
                require_unsigned(numbers[index]);
            }
            df_iso_apdu_v1 request{};
            request.struct_size = sizeof(request);
            request.abi_version = DF_ABI_VERSION;
            request.cla = static_cast<std::uint32_t>(numbers[0]);
            request.ins = static_cast<std::uint32_t>(numbers[1]);
            request.p1 = static_cast<std::uint32_t>(numbers[2]);
            request.p2 = static_cast<std::uint32_t>(numbers[3]);
            request.data = blobs[0].data();
            request.data_size = blobs[0].size();
            request.has_le = static_cast<std::uint32_t>(numbers[4]);
            request.le = static_cast<std::uint32_t>(numbers[5]);
            request.length_encoding = static_cast<std::uint32_t>(numbers[6]);
            request.correct_length = static_cast<std::uint32_t>(numbers[7]);
            request.maximum_response = size_value(numbers[8]);
            request.maximum_frames = size_value(numbers[9]);
            status = operation == 4
                         ? df_raw_iso_exchange(handle, &request, timeout_value(numbers[10]),
                                               &response_status, &output, &error)
                         : df_raw_iso_secure_exchange(handle, &request, timeout_value(numbers[10]),
                                                      &response_status, &output, &error);
            break;
        }
        case 5: {
            require_counts(numbers.size(), 10U, blobs.size(), 2U);
            for (std::size_t index : {0U, 1U, 2U, 3U, 7U, 8U}) {
                require_unsigned(numbers[index]);
            }
            df_native_secure_request_v1 request{};
            request.struct_size = sizeof(request);
            request.abi_version = DF_ABI_VERSION;
            request.profile = static_cast<std::uint32_t>(numbers[0]);
            request.command = static_cast<std::uint32_t>(numbers[1]);
            request.header = blobs[0].data();
            request.header_size = blobs[0].size();
            request.data = blobs[1].data();
            request.data_size = blobs[1].size();
            request.request_communication = static_cast<std::uint32_t>(numbers[2]);
            request.response_communication = static_cast<std::uint32_t>(numbers[3]);
            request.minimum_response = size_value(numbers[4]);
            request.maximum_response = size_value(numbers[5]);
            request.first_frame_data_size =
                numbers[6] == -1 ? DF_RAW_NO_FIRST_FRAME_BOUNDARY : size_value(numbers[6]);
            request.flags = numbers[7] != 0 ? DF_RAW_SINGLE_CONTINUATION : 0U;
            request.invalidates_session = numbers[8] != 0 ? 1U : 0U;
            status = df_raw_native_secure_exchange(handle, &request, timeout_value(numbers[9]),
                                                   &output, &error);
            break;
        }
        default:
            throw std::invalid_argument("raw operation");
        }
        if (status != DF_OK) {
            df_buffer_free(output);
            throw_error(env, error);
            return nullptr;
        }
        if (operation == 2 || operation == 3 || operation == 4 || operation == 6) {
            std::unique_ptr<df_buffer, decltype(&df_buffer_free)> owner(output, df_buffer_free);
            output = nullptr;
            const auto result = raw_result(response_status, owner.get());
            return to_java_bytes(env, result.data(), result.size());
        }
        return take_output(env, output, {});
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid raw JNI arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI raw handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "Raw JNI operation failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}

/** @brief Authenticate a raw channel with one copied direct AES-128 key. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_raw_RawNative_authenticateDirect(
    JNIEnv* env, jclass, jlong raw_handle, jint profile, jint key_number, jboolean application,
    jbyteArray key_input, jbyteArray capabilities_input, jlong timeout_input) {
    df_error error{};
    try {
        const auto handle = static_cast<df_raw_channel>(raw_handle);
        const auto context = retain_raw(handle);
        const auto key = copy_input(env, key_input, 16U);
        const auto capabilities = copy_input(env, capabilities_input, 6U);
        std::vector<std::uint8_t> result;
        if (authenticate_raw_direct(handle, profile, key_number, application, key, capabilities,
                                    timeout_value(timeout_input), result, &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return to_java_bytes(env, result.data(), result.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid raw authentication arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI raw handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Raw authentication bridge failed");
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Derive an AES-128 key in wiping native storage before raw authentication. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_raw_RawNative_authenticateDerived(
    JNIEnv* env, jclass, jlong raw_handle, jint profile, jint key_number, jboolean application,
    jbyteArray master_input, jbyteArray diversification_input, jbyteArray capabilities_input,
    jlong timeout_input) {
    df_error error{};
    try {
        const auto master = copy_input(env, master_input, 16U);
        const auto diversification = copy_input(env, diversification_input, 31U);
        auto key = derive_key(master, diversification, &error);
        const auto handle = static_cast<df_raw_channel>(raw_handle);
        const auto context = retain_raw(handle);
        const auto capabilities = copy_input(env, capabilities_input, 6U);
        std::vector<std::uint8_t> result;
        if (authenticate_raw_direct(handle, profile, key_number, application, key, capabilities,
                                    timeout_value(timeout_input), result, &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return to_java_bytes(env, result.data(), result.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid raw derived authentication arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI raw handle is closed");
    } catch (...) {
        if (error.code == DF_OK) {
            set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Raw derivation bridge failed");
        }
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Resolve one provider key before raw authentication. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_raw_RawNative_authenticateProvider(
    JNIEnv* env, jclass, jlong raw_handle, jint profile, jint scope, jint key_number,
    jboolean application, jobject bridge, jbyteArray reference, jbyteArray diversification,
    jbyteArray user_context, jint application_id, jint key_set, jbyteArray capabilities_input,
    jlong timeout_input) {
    df_error error{};
    try {
        const auto handle = static_cast<df_raw_channel>(raw_handle);
        const auto context = retain_raw(handle);
        ProviderArguments provider(env, bridge, DF_KEY_PURPOSE_AUTHENTICATION, profile, scope,
                                   key_number, application_id, key_set, reference, diversification,
                                   user_context);
        ActiveProvider active(context, provider.context);
        const auto capabilities = copy_input(env, capabilities_input, 6U);
        std::vector<std::uint8_t> result;
        const auto status =
            authenticate_raw_provider(handle, profile, key_number, application, provider,
                                      capabilities, timeout_value(timeout_input), result, &error);
        if (status != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return to_java_bytes(env, result.data(), result.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid raw provider authentication arguments");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI raw handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Raw provider bridge failed");
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Set the default application key from one copied AES-128 key. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_setDefaultAesKeyDirect(JNIEnv* env, jclass,
                                                                          jlong raw_handle,
                                                                          jbyteArray key_input,
                                                                          jint version,
                                                                          jlong timeout_input) {
    df_error error{};
    try {
        if (version < 0 || version > 0xFF) {
            throw std::invalid_argument("key version");
        }
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        const auto key = copy_input(env, key_input, 16U);
        if (df_set_default_aes_key(handle, key.data(), key.size(),
                                   static_cast<std::uint32_t>(version),
                                   timeout_value(timeout_input), &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        return;
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid default-key input");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "Default-key bridge failed");
    }
    throw_error(env, error);
}

/** @brief Derive and set the default application AES-128 key in wiping native storage. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_setDefaultAesKeyDerived(
    JNIEnv* env, jclass, jlong raw_handle, jbyteArray master_input,
    jbyteArray diversification_input, jint version, jlong timeout_input) {
    df_error error{};
    try {
        if (version < 0 || version > 0xFF) {
            throw std::invalid_argument("key version");
        }
        const auto master = copy_input(env, master_input, 16U);
        const auto diversification = copy_input(env, diversification_input, 31U);
        auto key = derive_key(master, diversification, &error);
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        if (df_set_default_aes_key(handle, key.data(), key.size(),
                                   static_cast<std::uint32_t>(version),
                                   timeout_value(timeout_input), &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        return;
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid derived default-key input");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        if (error.code == DF_OK) {
            set_error(&error, DF_INTERNAL, DF_UNKNOWN, "Derived default-key bridge failed");
        }
    }
    throw_error(env, error);
}

/** @brief Resolve and set the default application key before its first card frame. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_setDefaultAesKeyProvider(
    JNIEnv* env, jclass, jlong raw_handle, jint key_number, jobject bridge, jbyteArray reference,
    jbyteArray diversification, jbyteArray user_context, jint application_id, jint key_set,
    jint version, jlong timeout_input) {
    df_error error{};
    try {
        if (version < 0 || version > 0xFF) {
            throw std::invalid_argument("key version");
        }
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        ProviderArguments provider(env, bridge, DF_KEY_PURPOSE_REPLACEMENT_KEY, -1,
                                   DF_KEY_SCOPE_NATIVE, key_number, application_id, key_set,
                                   reference, diversification, user_context);
        ActiveProvider active(context, provider.context);
        if (df_set_default_aes_key_provider(handle, &provider.provider, &provider.request,
                                            static_cast<std::uint32_t>(version),
                                            timeout_value(timeout_input), &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        return;
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid provider default-key input");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "Provider default-key bridge failed");
    }
    throw_error(env, error);
}

/** @brief Resolve the AES key and create one transaction-MAC file. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_createTransactionMacFileProvider(
    JNIEnv* env, jclass, jlong raw_handle, jint file, jint access_rights, jint key_number,
    jobject bridge, jbyteArray reference, jbyteArray diversification, jbyteArray user_context,
    jint application_id, jint key_set, jint version, jlong timeout_input) {
    df_error error{};
    try {
        if (file < 0 || access_rights < 0 || version < 0 || version > 0xFF) {
            throw std::invalid_argument("transaction-MAC selector");
        }
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        ProviderArguments provider(env, bridge, DF_KEY_PURPOSE_TRANSACTION_MAC, -1,
                                   DF_KEY_SCOPE_NATIVE, key_number, application_id, key_set,
                                   reference, diversification, user_context);
        ActiveProvider active(context, provider.context);
        if (df_create_transaction_mac_file_provider(
                handle, static_cast<std::uint32_t>(file), static_cast<std::uint32_t>(access_rights),
                &provider.provider, &provider.request, static_cast<std::uint32_t>(version),
                timeout_value(timeout_input), &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        return;
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid provider transaction-MAC file input");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "Provider transaction-MAC file bridge failed");
    }
    throw_error(env, error);
}

/** @brief Resolve replacement and optional current AES keys before one key change. */
JNIEXPORT void JNICALL Java_com_desfire_ev3_Native_changeAesKeyProvider(
    JNIEnv* env, jclass, jlong raw_handle, jint number, jobject new_bridge,
    jbyteArray new_reference, jbyteArray new_diversification, jbyteArray new_user_context,
    jint new_application_id, jint new_key_set, jint version, jint authenticated_key,
    jobject old_bridge, jbyteArray old_reference, jbyteArray old_diversification,
    jbyteArray old_user_context, jint old_application_id, jint old_key_set, jint key_set,
    jboolean picc_master, jlong timeout_input) {
    df_error error{};
    try {
        if (number < 0 || authenticated_key < 0 || version < 0 || version > 0xFF || key_set < -1 ||
            key_set > 15 || picc_master > 1) {
            throw std::invalid_argument("key-change selector");
        }
        const auto handle = static_cast<df_card>(raw_handle);
        const auto context = retain_managed(handle);
        ProviderArguments replacement(env, new_bridge, DF_KEY_PURPOSE_REPLACEMENT_KEY, -1,
                                      DF_KEY_SCOPE_NATIVE, number, new_application_id, new_key_set,
                                      new_reference, new_diversification, new_user_context);
        std::unique_ptr<ProviderArguments> current;
        if (old_bridge) {
            current = std::make_unique<ProviderArguments>(
                env, old_bridge, DF_KEY_PURPOSE_CURRENT_KEY, -1, DF_KEY_SCOPE_NATIVE, number,
                old_application_id, old_key_set, old_reference, old_diversification,
                old_user_context);
        }
        ActiveProvider active_replacement(context, replacement.context);
        std::unique_ptr<ActiveProvider> active_current;
        if (current) {
            active_current = std::make_unique<ActiveProvider>(context, current->context);
        }
        if (df_change_aes_key_provider(
                handle, static_cast<std::uint32_t>(number), &replacement.provider,
                &replacement.request, static_cast<std::uint32_t>(version),
                static_cast<std::uint32_t>(authenticated_key),
                current ? &current->provider : nullptr, current ? &current->request : nullptr,
                key_set, picc_master ? 1U : 0U, timeout_value(timeout_input), &error) != DF_OK) {
            throw_error(env, error);
            return;
        }
        return;
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid provider key-change input");
    } catch (const std::out_of_range&) {
        set_error(&error, DF_STALE_HANDLE, DF_NOT_SENT, "JNI card handle is closed");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_UNKNOWN, "Provider key-change bridge failed");
    }
    throw_error(env, error);
}

/** @brief Derive one AES-128 key from copied direct inputs without card I/O. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_offline_OfflineNative_deriveDirect(
    JNIEnv* env, jclass, jbyteArray master_input, jbyteArray diversification_input) {
    df_error error{};
    try {
        const auto master = copy_input(env, master_input, 16U);
        const auto diversification = copy_input(env, diversification_input, 31U);
        auto key = derive_key(master, diversification, &error);
        return to_java_bytes(env, key.data(), key.size());
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid offline derivation input");
    } catch (...) {
        if (error.code == DF_OK) {
            set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Offline derivation bridge failed");
        }
    }
    throw_error(env, error);
    return nullptr;
}

/** @brief Resolve one provider master key and derive it without card I/O. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_offline_OfflineNative_deriveProvider(
    JNIEnv* env, jclass, jobject bridge, jint scope, jint key_number, jbyteArray reference,
    jbyteArray diversification, jbyteArray user_context, jint application_id, jint key_set) {
    df_error error{};
    df_buffer* output = nullptr;
    try {
        ProviderArguments provider(env, bridge, DF_KEY_PURPOSE_OFFLINE_OPERATION, -1, scope,
                                   key_number, application_id, key_set, reference, diversification,
                                   user_context);
        if (df_offline_derive_nxp_aes128_provider(&provider.provider, &provider.request, &output,
                                                  &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return take_output(env, output, {});
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid provider derivation input");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Provider derivation bridge failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}

/** @brief Calculate one AES transaction MAC from copied direct inputs. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_offline_OfflineNative_transactionMacDirect(
    JNIEnv* env, jclass, jbyteArray key_input, jlong counter, jbyteArray uid_input,
    jbyteArray transaction_input) {
    df_error error{};
    df_buffer* output = nullptr;
    try {
        require_unsigned(counter);
        const auto key = copy_input(env, key_input, 16U);
        const auto uid = copy_input(env, uid_input, 64U);
        const auto transaction = copy_input(env, transaction_input, 16U * 1024U * 1024U);
        if (df_offline_calculate_transaction_mac_aes(
                key.data(), key.size(), static_cast<std::uint32_t>(counter), uid.data(), uid.size(),
                transaction.data(), transaction.size(), &output, &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return take_output(env, output, {});
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid transaction-MAC input");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Transaction-MAC bridge failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}

/** @brief Resolve one provider transaction key and calculate its AES MAC. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_offline_OfflineNative_transactionMacProvider(
    JNIEnv* env, jclass, jobject bridge, jint scope, jint key_number, jbyteArray reference,
    jbyteArray diversification, jbyteArray user_context, jint application_id, jint key_set,
    jlong counter, jbyteArray uid_input, jbyteArray transaction_input) {
    df_error error{};
    df_buffer* output = nullptr;
    try {
        require_unsigned(counter);
        ProviderArguments provider(env, bridge, DF_KEY_PURPOSE_TRANSACTION_MAC, -1, scope,
                                   key_number, application_id, key_set, reference, diversification,
                                   user_context);
        const auto uid = copy_input(env, uid_input, 64U);
        const auto transaction = copy_input(env, transaction_input, 16U * 1024U * 1024U);
        if (df_offline_calculate_transaction_mac_aes_provider(
                &provider.provider, &provider.request, static_cast<std::uint32_t>(counter),
                uid.data(), uid.size(), transaction.data(), transaction.size(), &output,
                &error) != DF_OK) {
            throw_error(env, error);
            return nullptr;
        }
        return take_output(env, output, {});
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid provider transaction-MAC input");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Provider transaction-MAC bridge failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}

/** @brief Verify one secp224r1 UID originality signature without card I/O. */
JNIEXPORT jboolean JNICALL Java_com_desfire_ev3_offline_OfflineNative_verifyOriginality(
    JNIEnv* env, jclass, jbyteArray public_key_input, jbyteArray uid_input,
    jbyteArray signature_input) {
    df_error error{};
    try {
        const auto public_key = copy_input(env, public_key_input, 1024U);
        const auto uid = copy_input(env, uid_input, 64U);
        const auto signature = copy_input(env, signature_input, 1024U);
        std::uint32_t verified{};
        if (df_offline_verify_originality_uid_signature(
                "secp224r1", public_key.data(), public_key.size(), uid.data(), uid.size(),
                signature.data(), signature.size(), &verified, &error) != DF_OK) {
            throw_error(env, error);
            return JNI_FALSE;
        }
        return verified != 0U ? JNI_TRUE : JNI_FALSE;
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid originality input");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Originality bridge failed");
    }
    throw_error(env, error);
    return JNI_FALSE;
}

/** @brief Execute one stateless direct-key offline AES helper. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_offline_OfflineNative_invoke(
    JNIEnv* env, jclass, jint operation, jlongArray numeric_input, jobjectArray data_input) {
    df_error error{};
    df_buffer* output = nullptr;
    try {
        auto arguments = read_arguments(env, numeric_input, data_input);
        const auto& numbers = arguments.numbers;
        const auto& blobs = arguments.blobs;
        std::uint32_t verified{};
        std::int32_t status{};
        switch (operation) {
        case 0:
            require_counts(numbers.size(), 1U, blobs.size(), 2U);
            require_unsigned(numbers[0]);
            status = df_offline_encrypt_delegated_default_key_aes(
                blobs[0].data(), blobs[0].size(), blobs[1].data(), blobs[1].size(),
                static_cast<std::uint32_t>(numbers[0]), &output, &error);
            break;
        case 1: {
            require_counts(numbers.size(), 14U, blobs.size(), 3U);
            const auto configuration = delegated_configuration(numbers, blobs[1]);
            status = df_offline_calculate_delegated_application_mac_aes(
                blobs[0].data(), blobs[0].size(), &configuration, blobs[2].data(), blobs[2].size(),
                &output, &error);
            break;
        }
        case 2:
            require_counts(numbers.size(), 1U, blobs.size(), 1U);
            require_unsigned(numbers[0]);
            status = df_offline_calculate_delegated_application_delete_mac_aes(
                blobs[0].data(), blobs[0].size(), static_cast<std::uint32_t>(numbers[0]), &output,
                &error);
            break;
        case 3:
            require_counts(numbers.size(), 0U, blobs.size(), 3U);
            status = df_offline_calculate_delegated_configuration_mac_aes(
                blobs[0].data(), blobs[0].size(), blobs[1].data(), blobs[1].size(), blobs[2].data(),
                blobs[2].size(), &output, &error);
            break;
        case 4:
            require_counts(numbers.size(), 0U, blobs.size(), 3U);
            status = df_offline_calculate_mfc_license_mac_aes(
                blobs[0].data(), blobs[0].size(), blobs[1].data(), blobs[1].size(), blobs[2].data(),
                blobs[2].size(), &output, &error);
            break;
        case 5:
            require_counts(numbers.size(), 1U, blobs.size(), 2U);
            require_unsigned(numbers[0]);
            status = df_offline_derive_transaction_mac_keys_aes(
                blobs[0].data(), blobs[0].size(), static_cast<std::uint32_t>(numbers[0]),
                blobs[1].data(), blobs[1].size(), &output, &error);
            break;
        case 6:
            require_counts(numbers.size(), 0U, blobs.size(), 2U);
            status = df_offline_calculate_transaction_mac_session_aes(
                blobs[0].data(), blobs[0].size(), blobs[1].data(), blobs[1].size(), &output,
                &error);
            break;
        case 7:
            require_counts(numbers.size(), 1U, blobs.size(), 4U);
            require_unsigned(numbers[0]);
            status = df_offline_verify_transaction_mac_aes(
                blobs[0].data(), blobs[0].size(), static_cast<std::uint32_t>(numbers[0]),
                blobs[1].data(), blobs[1].size(), blobs[2].data(), blobs[2].size(), blobs[3].data(),
                blobs[3].size(), &verified, &error);
            break;
        case 8:
            require_counts(numbers.size(), 0U, blobs.size(), 2U);
            status = df_offline_decrypt_transaction_reader_id_aes(blobs[0].data(), blobs[0].size(),
                                                                  blobs[1].data(), blobs[1].size(),
                                                                  &output, &error);
            break;
        default:
            throw std::invalid_argument("offline operation");
        }
        if (status != DF_OK) {
            df_buffer_free(output);
            throw_error(env, error);
            return nullptr;
        }
        if (operation == 7) {
            const std::uint8_t result = verified != 0U ? 1U : 0U;
            return to_java_bytes(env, &result, 1U);
        }
        return take_output(env, output, {});
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT, "Invalid offline AES arguments");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Offline AES bridge failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}

/** @brief Execute one stateless provider-key offline AES helper. */
JNIEXPORT jbyteArray JNICALL Java_com_desfire_ev3_offline_OfflineNative_invokeProvider(
    JNIEnv* env, jclass, jint operation, jobject bridge, jint scope, jint key_number,
    jbyteArray reference, jbyteArray diversification, jbyteArray user_context, jint application_id,
    jint key_set, jlongArray numeric_input, jobjectArray data_input) {
    df_error error{};
    df_buffer* output = nullptr;
    try {
        auto arguments = read_arguments(env, numeric_input, data_input);
        const auto& numbers = arguments.numbers;
        const auto& blobs = arguments.blobs;
        const auto purpose = operation <= 4   ? DF_KEY_PURPOSE_DELEGATED_APPLICATION
                             : operation == 5 ? DF_KEY_PURPOSE_OFFLINE_OPERATION
                                              : DF_KEY_PURPOSE_TRANSACTION_MAC;
        ProviderArguments provider(env, bridge, static_cast<jint>(purpose), -1, scope, key_number,
                                   application_id, key_set, reference, diversification,
                                   user_context);
        std::uint32_t verified{};
        std::int32_t status{};
        switch (operation) {
        case 0:
            require_counts(numbers.size(), 1U, blobs.size(), 1U);
            require_unsigned(numbers[0]);
            status = df_offline_encrypt_delegated_default_key_aes_provider(
                &provider.provider, &provider.request, blobs[0].data(), blobs[0].size(),
                static_cast<std::uint32_t>(numbers[0]), &output, &error);
            break;
        case 1: {
            require_counts(numbers.size(), 14U, blobs.size(), 2U);
            const auto configuration = delegated_configuration(numbers, blobs[0]);
            status = df_offline_calculate_delegated_application_mac_aes_provider(
                &provider.provider, &provider.request, &configuration, blobs[1].data(),
                blobs[1].size(), &output, &error);
            break;
        }
        case 2:
            require_counts(numbers.size(), 1U, blobs.size(), 0U);
            require_unsigned(numbers[0]);
            status = df_offline_calculate_delegated_application_delete_mac_aes_provider(
                &provider.provider, &provider.request, static_cast<std::uint32_t>(numbers[0]),
                &output, &error);
            break;
        case 3:
            require_counts(numbers.size(), 0U, blobs.size(), 2U);
            status = df_offline_calculate_delegated_configuration_mac_aes_provider(
                &provider.provider, &provider.request, blobs[0].data(), blobs[0].size(),
                blobs[1].data(), blobs[1].size(), &output, &error);
            break;
        case 4:
            require_counts(numbers.size(), 0U, blobs.size(), 2U);
            status = df_offline_calculate_mfc_license_mac_aes_provider(
                &provider.provider, &provider.request, blobs[0].data(), blobs[0].size(),
                blobs[1].data(), blobs[1].size(), &output, &error);
            break;
        case 5:
            require_counts(numbers.size(), 1U, blobs.size(), 1U);
            require_unsigned(numbers[0]);
            status = df_offline_derive_transaction_mac_keys_aes_provider(
                &provider.provider, &provider.request, static_cast<std::uint32_t>(numbers[0]),
                blobs[0].data(), blobs[0].size(), &output, &error);
            break;
        case 6:
            require_counts(numbers.size(), 1U, blobs.size(), 2U);
            require_unsigned(numbers[0]);
            status = df_offline_calculate_transaction_mac_aes_provider(
                &provider.provider, &provider.request, static_cast<std::uint32_t>(numbers[0]),
                blobs[0].data(), blobs[0].size(), blobs[1].data(), blobs[1].size(), &output,
                &error);
            break;
        case 7:
            require_counts(numbers.size(), 1U, blobs.size(), 3U);
            require_unsigned(numbers[0]);
            status = df_offline_verify_transaction_mac_aes_provider(
                &provider.provider, &provider.request, static_cast<std::uint32_t>(numbers[0]),
                blobs[0].data(), blobs[0].size(), blobs[1].data(), blobs[1].size(), blobs[2].data(),
                blobs[2].size(), &verified, &error);
            break;
        default:
            throw std::invalid_argument("provider offline operation");
        }
        if (status != DF_OK) {
            df_buffer_free(output);
            throw_error(env, error);
            return nullptr;
        }
        if (operation == 7) {
            const std::uint8_t result = verified != 0U ? 1U : 0U;
            return to_java_bytes(env, &result, 1U);
        }
        return take_output(env, output, {});
    } catch (const std::invalid_argument&) {
        set_error(&error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                  "Invalid provider offline AES arguments");
    } catch (...) {
        set_error(&error, DF_INTERNAL, DF_NOT_SENT, "Provider offline AES bridge failed");
    }
    df_buffer_free(output);
    throw_error(env, error);
    return nullptr;
}
} // extern "C"
