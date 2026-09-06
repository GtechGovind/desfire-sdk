/** @file key_provider.hpp
 * @brief JNI bridge for synchronous scoped AES-128 providers.
 */
#pragma once

#include "context.hpp"

#include <atomic>
#include <memory>

namespace desfire::jni {
    /** @brief Global Java provider reference and cooperative cancellation state for one call. */
    struct ProviderContext final {
        JavaVM* vm{};
        jobject bridge{};
        jmethodID resolve{};
        std::atomic_bool cancelled{false};

        /** @brief Release the provider global reference from an attached thread. */
        ~ProviderContext();
    };

    /** @brief Provider descriptor and request whose borrowed arrays outlive one C call. */
    struct ProviderArguments final {
        std::shared_ptr<ProviderContext> context;
        InputBytes reference;
        InputBytes diversification;
        InputBytes user_context;
        df_key_provider_v1 provider{};
        df_key_request_v1 request{};

        /** @brief Build fully versioned C descriptors from copied Java inputs. */
        ProviderArguments(JNIEnv* env, jobject bridge, jint purpose, jint profile, jint scope,
                          jint key_number, jint application_id, jint key_set, jbyteArray reference,
                          jbyteArray diversification, jbyteArray user_context);
        ProviderArguments(const ProviderArguments&) = delete;
        ProviderArguments& operator=(const ProviderArguments&) = delete;
    };

    /** @brief Publish one active provider to the transport cancellation path. */
    class ActiveProvider final {
    public:

        /** @brief Register provider cancellation before entering the C authentication call. */
        ActiveProvider(std::shared_ptr<TransportContext> transport,
                       std::shared_ptr<ProviderContext> provider);
        ActiveProvider(const ActiveProvider&) = delete;
        ActiveProvider& operator=(const ActiveProvider&) = delete;
        /** @brief Remove the provider from the cancellation path. */
        ~ActiveProvider();

    private:

        std::shared_ptr<TransportContext> transport_;
        std::shared_ptr<ProviderContext> provider_;
    };

} // namespace desfire::jni
