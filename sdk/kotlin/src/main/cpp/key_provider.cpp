/** @file key_provider.cpp
 * @brief Exactly-once Java key-provider invocation with redacted failures.
 */
#include "key_provider.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace desfire::jni {
    namespace {
        /** @brief Copy one Java byte array into wiping native storage. */
        InputBytes copy_bytes(JNIEnv* env, jbyteArray input, std::size_t maximum,
                              bool require_nonempty) {
            if (!input) {
                throw std::invalid_argument("provider bytes");
            }
            const auto size = static_cast<std::size_t>(env->GetArrayLength(input));
            if (size > maximum || (require_nonempty && size == 0U)) {
                throw std::invalid_argument("provider byte count");
            }
            InputBytes result(size);
            env->GetByteArrayRegion(input, 0, static_cast<jsize>(size),
                                    reinterpret_cast<jbyte*>(result.bytes.data()));
            if (env->ExceptionCheck()) {
                throw std::invalid_argument("provider byte copy");
            }
            return result;
        }

        /** @brief Report the current cooperative provider cancellation flag. */
        std::uint32_t provider_cancelled(void* opaque) noexcept {
            const auto& context = *static_cast<ProviderContext*>(opaque);
            return context.cancelled.load(std::memory_order_acquire) ? 1U : 0U;
        }

        /** @brief Invoke the internal ProviderBridge method exactly once. */
        std::int32_t provider_resolve(void* opaque, const df_key_request_v1* request,
                                      std::uint8_t* key, std::size_t capacity, std::size_t* written,
                                      df_error* error) noexcept {
            try {
                auto& context = *static_cast<ProviderContext*>(opaque);
                if (!request || !key || !written || capacity != 16U) {
                    return set_error(error, DF_INVALID_ARGUMENT, DF_NOT_SENT,
                                     "Invalid Java key-provider output");
                }
                if (context.cancelled.load(std::memory_order_acquire)) {
                    return set_error(error, DF_CANCELLED, DF_NOT_SENT,
                                     "Key resolution was cancelled");
                }
                Environment current(context.vm);
                auto* env = current.env;
                if (!env || env->PushLocalFrame(12) < 0) {
                    return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                     "Cannot attach Java provider thread");
                }
                const auto reference =
                    to_java_bytes(env, request->reference, request->reference_size);
                const auto diversification =
                    to_java_bytes(env, request->diversification, request->diversification_size);
                const auto user_context =
                    to_java_bytes(env, request->user_context, request->user_context_size);
                if (env->ExceptionCheck() || !reference || !diversification || !user_context) {
                    env->ExceptionClear();
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                     "Cannot copy Java provider request");
                }
                const auto application_id = request->application_id == DF_OPTION_ABSENT
                                                ? -1
                                                : static_cast<jint>(request->application_id);
                const auto key_set =
                    request->key_set == DF_OPTION_ABSENT ? -1 : static_cast<jint>(request->key_set);
                const auto output = static_cast<jbyteArray>(env->CallObjectMethod(
                    context.bridge, context.resolve, static_cast<jint>(request->purpose),
                    static_cast<jint>(request->authentication_profile),
                    static_cast<jint>(request->scope), static_cast<jint>(request->key_number),
                    application_id, key_set, reference, diversification, user_context,
                    static_cast<jboolean>(context.cancelled.load(std::memory_order_acquire))));
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_CRYPTO, DF_NOT_SENT, "AES-128 key provider failed");
                }
                if (!output || env->GetArrayLength(output) != 16) {
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_CRYPTO, DF_NOT_SENT,
                                     "AES-128 key provider returned an invalid key");
                }
                env->GetByteArrayRegion(output, 0, 16, reinterpret_cast<jbyte*>(key));
                std::array<jbyte, 16> zeros{};
                env->SetByteArrayRegion(output, 0, 16, zeros.data());
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    std::fill_n(key, capacity, std::uint8_t{});
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                     "Cannot copy Java provider result");
                }
                if (context.cancelled.load(std::memory_order_acquire)) {
                    std::fill_n(key, capacity, std::uint8_t{});
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_CANCELLED, DF_NOT_SENT,
                                     "Key resolution was cancelled");
                }
                *written = 16U;
                env->PopLocalFrame(nullptr);
                return DF_OK;
            } catch (...) {
                return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                 "Java key-provider bridge failed");
            }
        }
    } // namespace

    ProviderContext::~ProviderContext() {
        Environment current(vm);
        if (current.env && bridge) {
            current.env->DeleteGlobalRef(bridge);
        }
    }

    ProviderArguments::ProviderArguments(JNIEnv* env, jobject java_bridge, jint purpose,
                                         jint profile, jint scope, jint key_number,
                                         jint application_id, jint key_set,
                                         jbyteArray reference_input,
                                         jbyteArray diversification_input,
                                         jbyteArray user_context_input)
        : context(std::make_shared<ProviderContext>()),
          reference(copy_bytes(env, reference_input, 1024U, true)),
          diversification(copy_bytes(env, diversification_input, 65536U, false)),
          user_context(copy_bytes(env, user_context_input, 65536U, false)) {
        if (!java_bridge || purpose < 0 || purpose > 5 || profile < -1 || profile > 3 ||
            scope < 0 || scope > 2 || key_number < 0 || application_id < -1 ||
            application_id > 0xFFFFFF || key_set < -1 || key_set > 15 ||
            diversification.size() + user_context.size() > 65536U ||
            env->GetJavaVM(&context->vm) != JNI_OK) {
            throw std::invalid_argument("provider metadata");
        }
        context->bridge = env->NewGlobalRef(java_bridge);
        const auto bridge_class = env->GetObjectClass(java_bridge);
        context->resolve = env->GetMethodID(bridge_class, "resolve", "(IIIIII[B[B[BZ)[B");
        env->DeleteLocalRef(bridge_class);
        if (env->ExceptionCheck() || !context->bridge || !context->resolve) {
            throw std::invalid_argument("provider callback");
        }
        provider.struct_size = sizeof(provider);
        provider.abi_version = DF_ABI_VERSION;
        provider.context = context.get();
        provider.resolve = provider_resolve;

        request.struct_size = sizeof(request);
        request.abi_version = DF_ABI_VERSION;
        request.purpose = static_cast<std::uint32_t>(purpose);
        request.authentication_profile =
            profile < 0 ? DF_OPTION_ABSENT : static_cast<std::uint32_t>(profile);
        request.scope = static_cast<std::uint32_t>(scope);
        request.key_number = static_cast<std::uint32_t>(key_number);
        request.application_id =
            application_id < 0 ? DF_OPTION_ABSENT : static_cast<std::uint32_t>(application_id);
        request.key_set = key_set < 0 ? DF_OPTION_ABSENT : static_cast<std::uint32_t>(key_set);
        request.reference = reference.data();
        request.reference_size = reference.size();
        request.diversification = diversification.data();
        request.diversification_size = diversification.size();
        request.user_context = user_context.data();
        request.user_context_size = user_context.size();
        request.cancellation_context = context.get();
        request.is_cancelled = provider_cancelled;
    }

    ActiveProvider::ActiveProvider(std::shared_ptr<TransportContext> transport,
                                   std::shared_ptr<ProviderContext> provider)
        : transport_(std::move(transport)), provider_(std::move(provider)) {
        transport_->set_provider(provider_);
    }

    ActiveProvider::~ActiveProvider() {
        transport_->clear_provider(provider_);
    }

} // namespace desfire::jni
