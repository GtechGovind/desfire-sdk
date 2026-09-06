/** @file transport.cpp
 * @brief Exact-once Java physical exchange callbacks.
 */
#include "transport.hpp"

#include <algorithm>
#include <climits>
#include <stdexcept>

namespace desfire::jni {
    namespace {
        /** @brief Copy one physical request to Java and bound its complete response. */
        std::int32_t exchange_callback(void* opaque, const std::uint8_t* request,
                                       std::size_t request_size, std::uint8_t* response,
                                       std::size_t capacity, std::size_t* received,
                                       std::uint32_t timeout, df_error* error) noexcept {
            try {
                auto& context = *static_cast<TransportContext*>(opaque);
                Environment current(context.vm);
                auto* env = current.env;
                if (!env || env->PushLocalFrame(8) < 0) {
                    return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                     "Cannot attach Java exchange thread");
                }
                const auto frame = env->NewByteArray(static_cast<jsize>(request_size));
                if (!frame) {
                    env->ExceptionClear();
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                     "Cannot allocate Java request");
                }
                env->SetByteArrayRegion(frame, 0, static_cast<jsize>(request_size),
                                        reinterpret_cast<const jbyte*>(request));
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_INTERNAL, DF_NOT_SENT, "Cannot copy Java request");
                }
                const auto bounded =
                    std::min<std::uint32_t>(timeout, static_cast<std::uint32_t>(INT32_MAX));
                const auto output = static_cast<jbyteArray>(env->CallObjectMethod(
                    context.transport, context.exchange, frame, static_cast<jint>(bounded)));
                if (env->ExceptionCheck()) {
                    const auto status = callback_exception(context, env, error);
                    env->PopLocalFrame(nullptr);
                    return status;
                }
                if (!output || static_cast<std::size_t>(env->GetArrayLength(output)) > capacity) {
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_MALFORMED_RESPONSE, DF_UNKNOWN,
                                     "Java response exceeds capacity or is null");
                }
                *received = static_cast<std::size_t>(env->GetArrayLength(output));
                env->GetByteArrayRegion(output, 0, static_cast<jsize>(*received),
                                        reinterpret_cast<jbyte*>(response));
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    env->PopLocalFrame(nullptr);
                    return set_error(error, DF_INTERNAL, DF_UNKNOWN, "Cannot copy Java response");
                }
                env->PopLocalFrame(nullptr);
                return DF_OK;
            } catch (...) {
                return set_error(error, DF_INTERNAL, DF_UNKNOWN, "JNI exchange callback failed");
            }
        }

        /** @brief Forward cancellation independently of operation serialization. */
        void cancel_callback(void* opaque) noexcept {
            auto& context = *static_cast<TransportContext*>(opaque);
            Environment current(context.vm);
            if (!current.env) {
                return;
            }
            current.env->CallVoidMethod(context.transport, context.cancel);
            if (current.env->ExceptionCheck()) {
                current.env->ExceptionClear();
            }
        }

        /** @brief Forward an explicit reset while preserving typed callback evidence. */
        std::int32_t reset_callback(void* opaque, df_error* error) noexcept {
            auto& context = *static_cast<TransportContext*>(opaque);
            Environment current(context.vm);
            if (!current.env) {
                return set_error(error, DF_INTERNAL, DF_NOT_SENT,
                                 "Cannot attach Java reset thread");
            }
            current.env->CallVoidMethod(context.transport, context.reset);
            if (current.env->ExceptionCheck()) {
                return callback_exception(context, current.env, error);
            }
            return DF_OK;
        }
    } // namespace

    std::shared_ptr<TransportContext> make_transport_context(JNIEnv* env, jobject transport) {
        auto context = std::make_shared<TransportContext>();
        if (!transport || env->GetJavaVM(&context->vm) != JNI_OK) {
            throw std::invalid_argument("transport");
        }
        context->transport = env->NewGlobalRef(transport);
        const auto transport_class = env->GetObjectClass(transport);
        context->exchange = env->GetMethodID(transport_class, "exchange", "([BI)[B");
        context->cancel = env->GetMethodID(transport_class, "cancel", "()V");
        context->reset = env->GetMethodID(transport_class, "reset", "()V");
        env->DeleteLocalRef(transport_class);
        const auto error_class = env->FindClass("com/desfire/ev3/DesfireException");
        if (!error_class || env->ExceptionCheck()) {
            throw std::invalid_argument("error class");
        }
        context->error_class = static_cast<jclass>(env->NewGlobalRef(error_class));
        context->error_code = env->GetMethodID(error_class, "getCode", "()I");
        context->error_outcome = env->GetMethodID(error_class, "getOutcome", "()I");
        context->error_status = env->GetMethodID(error_class, "getDeviceStatus", "()I");
        env->DeleteLocalRef(error_class);
        if (env->ExceptionCheck() || !context->transport || !context->error_class ||
            !context->exchange || !context->cancel || !context->reset || !context->error_code ||
            !context->error_outcome || !context->error_status) {
            throw std::invalid_argument("transport callbacks");
        }
        return context;
    }

    df_transport_v1 make_transport_descriptor(TransportContext& context, jint framing,
                                              jint max_transmit, jint max_receive,
                                              jint max_native_frame) {
        if (framing < 0 || framing > 1 || max_transmit < 0 || max_receive < 0 ||
            max_native_frame < 0) {
            throw std::invalid_argument("transport limits");
        }
        df_transport_v1 descriptor{};
        descriptor.struct_size = sizeof(descriptor);
        descriptor.abi_version = DF_ABI_VERSION;
        descriptor.framing = static_cast<std::uint32_t>(framing);
        descriptor.max_transmit = static_cast<std::uint32_t>(max_transmit);
        descriptor.max_receive = static_cast<std::uint32_t>(max_receive);
        descriptor.max_native_frame = static_cast<std::uint32_t>(max_native_frame);
        descriptor.context = &context;
        descriptor.exchange = exchange_callback;
        descriptor.cancel = cancel_callback;
        descriptor.reset = reset_callback;
        return descriptor;
    }
} // namespace desfire::jni
