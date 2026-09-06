/** @file context.cpp
 * @brief Shared JNI memory, exception, and handle-registry implementation.
 */
#include "context.hpp"

#include "key_provider.hpp"

#include <algorithm>
#include <climits>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <unordered_map>

namespace desfire::jni {
    namespace {
        std::mutex registry_mutex;
        std::unordered_map<df_card, std::shared_ptr<TransportContext>> managed_contexts;
        std::unordered_map<df_raw_channel, std::shared_ptr<TransportContext>> raw_contexts;

        /** @brief Retain one exact typed handle from its registry. */
        template <typename Handle>
        std::shared_ptr<TransportContext>
        retain_from(Handle handle,
                    const std::unordered_map<Handle, std::shared_ptr<TransportContext>>& registry) {
            std::lock_guard lock(registry_mutex);
            const auto found = registry.find(handle);
            if (found == registry.end()) {
                throw std::out_of_range("stale handle");
            }
            return found->second;
        }
    } // namespace

    InputBytes::InputBytes(std::size_t size) : bytes(size) {}

    InputBytes::~InputBytes() {
        volatile std::uint8_t* destination = bytes.data();
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            destination[index] = 0;
        }
    }

    const std::uint8_t* InputBytes::data() const noexcept {
        return bytes.data();
    }

    std::size_t InputBytes::size() const noexcept {
        return bytes.size();
    }

    Environment::Environment(JavaVM* vm) : vm_(vm) {
        if (!vm_) {
            return;
        }
        void* raw = nullptr;
        const auto status = vm_->GetEnv(&raw, JNI_VERSION_1_6);
        if (status == JNI_OK) {
            env = static_cast<JNIEnv*>(raw);
        } else if (status == JNI_EDETACHED) {
#ifdef __ANDROID__
            JNIEnv* attached = nullptr;
            if (vm_->AttachCurrentThread(&attached, nullptr) == JNI_OK) {
                env = attached;
                attached_ = true;
            }
#else
            if (vm_->AttachCurrentThread(&raw, nullptr) == JNI_OK) {
                env = static_cast<JNIEnv*>(raw);
                attached_ = true;
            }
#endif
        }
    }

    Environment::~Environment() {
        if (attached_) {
            vm_->DetachCurrentThread();
        }
    }

    TransportContext::~TransportContext() {
        Environment current(vm);
        if (!current.env) {
            return;
        }
        if (transport) {
            current.env->DeleteGlobalRef(transport);
        }
        if (error_class) {
            current.env->DeleteGlobalRef(error_class);
        }
    }

    void TransportContext::set_provider(const std::shared_ptr<ProviderContext>& current) {
        std::lock_guard lock(provider_mutex);
        providers.erase(std::remove_if(providers.begin(), providers.end(),
                                       [](const auto& provider) { return provider.expired(); }),
                        providers.end());
        providers.emplace_back(current);
    }

    void TransportContext::clear_provider(const std::shared_ptr<ProviderContext>& current) {
        std::lock_guard lock(provider_mutex);
        providers.erase(std::remove_if(providers.begin(), providers.end(),
                                       [&](const auto& provider) {
                                           const auto retained = provider.lock();
                                           return !retained || retained == current;
                                       }),
                        providers.end());
    }

    void TransportContext::cancel_provider() {
        std::lock_guard lock(provider_mutex);
        for (auto iterator = providers.begin(); iterator != providers.end();) {
            if (const auto current = iterator->lock()) {
                current->cancelled.store(true, std::memory_order_release);
                ++iterator;
            } else {
                iterator = providers.erase(iterator);
            }
        }
    }

    std::int32_t set_error(df_error* error, std::uint32_t code, std::uint32_t outcome,
                           const char* message) noexcept {
        if (!error) {
            return static_cast<std::int32_t>(code);
        }
        *error = {};
        error->code = code;
        error->outcome = outcome;
        std::strncpy(error->message, message, sizeof(error->message) - 1U);
        return static_cast<std::int32_t>(code);
    }

    void throw_error(JNIEnv* env, const df_error& error) noexcept {
        if (!env || env->ExceptionCheck()) {
            return;
        }
        const auto klass = env->FindClass("com/desfire/ev3/DesfireException");
        if (!klass) {
            return;
        }
        const auto constructor = env->GetMethodID(klass, "<init>", "(IIILjava/lang/String;)V");
        const auto message = env->NewStringUTF(error.message);
        if (constructor && message) {
            const auto exception = env->NewObject(klass, constructor, static_cast<jint>(error.code),
                                                  static_cast<jint>(error.outcome),
                                                  static_cast<jint>(error.device_status), message);
            if (exception) {
                env->Throw(static_cast<jthrowable>(exception));
                env->DeleteLocalRef(exception);
            }
        }
        if (message) {
            env->DeleteLocalRef(message);
        }
        env->DeleteLocalRef(klass);
    }

    std::int32_t callback_exception(TransportContext& context, JNIEnv* env,
                                    df_error* error) noexcept {
        const auto exception = env->ExceptionOccurred();
        env->ExceptionClear();
        set_error(error, DF_TRANSPORT, DF_UNKNOWN, "Java transport callback failed");
        if (exception && env->IsInstanceOf(exception, context.error_class)) {
            const auto code = env->CallIntMethod(exception, context.error_code);
            const auto outcome = env->CallIntMethod(exception, context.error_outcome);
            const auto status = env->CallIntMethod(exception, context.error_status);
            if (!env->ExceptionCheck() && code >= DF_INVALID_ARGUMENT && code <= DF_INTERNAL &&
                outcome >= 0 && outcome <= static_cast<jint>(DF_UNKNOWN) && status >= 0 &&
                status <= 65535) {
                error->code = static_cast<std::uint32_t>(code);
                error->outcome = static_cast<std::uint32_t>(outcome);
                error->device_status = static_cast<std::uint16_t>(status);
            }
            env->ExceptionClear();
        }
        if (exception) {
            env->DeleteLocalRef(exception);
        }
        return static_cast<std::int32_t>(error->code);
    }

    Arguments read_arguments(JNIEnv* env, jlongArray numeric_input, jobjectArray data_input) {
        if (!numeric_input || !data_input) {
            throw std::invalid_argument("null arguments");
        }
        const auto number_count = env->GetArrayLength(numeric_input);
        const auto blob_count = env->GetArrayLength(data_input);
        if (number_count > 32 || blob_count > 8) {
            throw std::invalid_argument("argument count");
        }
        Arguments result;
        result.numbers.resize(static_cast<std::size_t>(number_count));
        env->GetLongArrayRegion(numeric_input, 0, number_count, result.numbers.data());
        if (env->ExceptionCheck()) {
            throw std::invalid_argument("numeric input");
        }
        result.blobs.reserve(static_cast<std::size_t>(blob_count));
        for (jsize index = 0; index < blob_count; ++index) {
            const auto item =
                static_cast<jbyteArray>(env->GetObjectArrayElement(data_input, index));
            if (!item || env->ExceptionCheck()) {
                throw std::invalid_argument("null byte array");
            }
            const auto size = env->GetArrayLength(item);
            if (size > 16 * 1024 * 1024) {
                env->DeleteLocalRef(item);
                throw std::invalid_argument("byte array size");
            }
            result.blobs.emplace_back(static_cast<std::size_t>(size));
            env->GetByteArrayRegion(item, 0, size,
                                    reinterpret_cast<jbyte*>(result.blobs.back().bytes.data()));
            env->DeleteLocalRef(item);
            if (env->ExceptionCheck()) {
                throw std::invalid_argument("byte array copy");
            }
        }
        return result;
    }

    jbyteArray to_java_bytes(JNIEnv* env, const std::uint8_t* data, std::size_t size) {
        if (size > static_cast<std::size_t>(INT32_MAX)) {
            throw std::length_error("Java output size");
        }
        const auto output = env->NewByteArray(static_cast<jsize>(size));
        if (output && size != 0U) {
            env->SetByteArrayRegion(output, 0, static_cast<jsize>(size),
                                    reinterpret_cast<const jbyte*>(data));
        }
        return output;
    }

    jbyteArray take_output(JNIEnv* env, df_buffer*& output,
                           const std::vector<std::uint8_t>& scalar) {
        std::unique_ptr<df_buffer, decltype(&df_buffer_free)> owner(output, df_buffer_free);
        output = nullptr;
        const auto size = owner ? df_buffer_size(owner.get()) : scalar.size();
        const auto* data = owner ? df_buffer_data(owner.get()) : scalar.data();
        return to_java_bytes(env, data, size);
    }

    void require_counts(std::size_t numeric, std::size_t expected_numeric, std::size_t blobs,
                        std::size_t expected_blobs) {
        if (numeric != expected_numeric || blobs != expected_blobs) {
            throw std::invalid_argument("argument count");
        }
    }

    void require_unsigned(jlong value) {
        if (value < 0 || static_cast<std::uint64_t>(value) > UINT32_MAX) {
            throw std::invalid_argument("unsigned range");
        }
    }

    void require_signed(jlong value) {
        if (value < INT32_MIN || value > INT32_MAX) {
            throw std::invalid_argument("signed range");
        }
    }

    std::shared_ptr<TransportContext> retain_managed(df_card handle) {
        return retain_from(handle, managed_contexts);
    }

    std::shared_ptr<TransportContext> retain_raw(df_raw_channel handle) {
        return retain_from(handle, raw_contexts);
    }

    void insert_managed(df_card handle, std::shared_ptr<TransportContext> context) {
        std::lock_guard lock(registry_mutex);
        if (!managed_contexts.emplace(handle, std::move(context)).second) {
            throw std::logic_error("duplicate managed handle");
        }
    }

    void insert_raw(df_raw_channel handle, std::shared_ptr<TransportContext> context) {
        std::lock_guard lock(registry_mutex);
        if (!raw_contexts.emplace(handle, std::move(context)).second) {
            throw std::logic_error("duplicate raw handle");
        }
    }

    void erase_managed(df_card handle) {
        std::lock_guard lock(registry_mutex);
        managed_contexts.erase(handle);
    }

    void erase_raw(df_raw_channel handle) {
        std::lock_guard lock(registry_mutex);
        raw_contexts.erase(handle);
    }
} // namespace desfire::jni
