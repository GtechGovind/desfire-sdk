/** @file context.hpp
 * @brief Shared JNI lifetime, argument, error, and registry primitives.
 */
#pragma once

#include <desfire.h>
#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace desfire::jni {
    struct ProviderContext;

    /** @brief Wipe one copied Java byte array before releasing its storage. */
    class InputBytes final {
    public:

        std::vector<std::uint8_t> bytes;

        /** @brief Allocate the exact validated Java array length. */
        explicit InputBytes(std::size_t size);
        InputBytes(InputBytes&&) noexcept = default;
        InputBytes(const InputBytes&) = delete;
        InputBytes& operator=(const InputBytes&) = delete;
        InputBytes& operator=(InputBytes&&) = delete;
        /** @brief Erase bytes through volatile stores. */
        ~InputBytes();

        /** @brief Borrow copied bytes during one C call. */
        [[nodiscard]] const std::uint8_t* data() const noexcept;
        /** @brief Return the copied byte count. */
        [[nodiscard]] std::size_t size() const noexcept;
    };

    /** @brief Attach foreign threads to the VM and detach only threads attached here. */
    class Environment final {
    public:

        /** @brief Obtain a JNIEnv for the current thread. */
        explicit Environment(JavaVM* vm);
        Environment(const Environment&) = delete;
        Environment& operator=(const Environment&) = delete;
        /** @brief Detach only a thread attached by this object. */
        ~Environment();

        JNIEnv* env{}; /**< Borrowed environment, or null when attachment failed. */

    private:

        JavaVM* vm_{};
        bool attached_{};
    };

    /** @brief Global Java transport references retained for one C handle. */
    struct TransportContext final {
        JavaVM* vm{};
        jobject transport{};
        jclass error_class{};
        jmethodID exchange{};
        jmethodID cancel{};
        jmethodID reset{};
        jmethodID error_code{};
        jmethodID error_outcome{};
        jmethodID error_status{};
        std::mutex provider_mutex;
        std::vector<std::weak_ptr<ProviderContext>> providers;

        /** @brief Release global references from a valid attached thread. */
        ~TransportContext();
        /** @brief Publish the provider currently resolving for cancellation. */
        void set_provider(const std::shared_ptr<ProviderContext>& current);
        /** @brief Remove the provider after its authentication call returns. */
        void clear_provider(const std::shared_ptr<ProviderContext>& current);
        /** @brief Mark an active provider resolution cancelled. */
        void cancel_provider();
    };

    /** @brief Copied, bounded generic-dispatch arguments. */
    struct Arguments final {
        std::vector<jlong> numbers;
        std::vector<InputBytes> blobs;
    };

    /** @brief Fill a stable, redacted C error. */
    std::int32_t set_error(df_error* error, std::uint32_t code, std::uint32_t outcome,
                           const char* message) noexcept;
    /** @brief Throw DesfireException unless Java already has a pending exception. */
    void throw_error(JNIEnv* env, const df_error& error) noexcept;
    /** @brief Convert a transport callback exception into stable C evidence. */
    std::int32_t callback_exception(TransportContext& context, JNIEnv* env,
                                    df_error* error) noexcept;
    /** @brief Copy bounded Java numeric and byte-array inputs. */
    Arguments read_arguments(JNIEnv* env, jlongArray numbers, jobjectArray blobs);
    /** @brief Copy a native byte span into a new Java array. */
    jbyteArray to_java_bytes(JNIEnv* env, const std::uint8_t* data, std::size_t size);
    /** @brief Copy a C owned buffer or scalar vector and release C ownership. */
    jbyteArray take_output(JNIEnv* env, df_buffer*& output,
                           const std::vector<std::uint8_t>& scalar);
    /** @brief Reject malformed internal dispatch argument counts. */
    void require_counts(std::size_t numeric, std::size_t expected_numeric, std::size_t blobs,
                        std::size_t expected_blobs);
    /** @brief Reject values that cannot narrow to uint32_t. */
    void require_unsigned(jlong value);
    /** @brief Reject values that cannot narrow to int32_t. */
    void require_signed(jlong value);

    /** @brief Retain one managed transport context across a JNI call. */
    std::shared_ptr<TransportContext> retain_managed(df_card handle);
    /** @brief Retain one raw transport context across a JNI call. */
    std::shared_ptr<TransportContext> retain_raw(df_raw_channel handle);
    /** @brief Publish one newly opened managed handle. */
    void insert_managed(df_card handle, std::shared_ptr<TransportContext> context);
    /** @brief Publish one newly opened raw handle. */
    void insert_raw(df_raw_channel handle, std::shared_ptr<TransportContext> context);
    /** @brief Erase one successfully closed managed handle. */
    void erase_managed(df_card handle);
    /** @brief Erase one successfully closed raw handle. */
    void erase_raw(df_raw_channel handle);
} // namespace desfire::jni
