/** @file transport.hpp
 * @brief Java transport callback construction for managed and raw JNI handles.
 */
#pragma once

#include "context.hpp"

namespace desfire::jni {
    /** @brief Validate and retain one Java CardTransport object. */
    std::shared_ptr<TransportContext> make_transport_context(JNIEnv* env, jobject transport);
    /** @brief Build an ABI-v1 descriptor borrowing the retained context. */
    df_transport_v1 make_transport_descriptor(TransportContext& context, jint framing,
                                              jint max_transmit, jint max_receive,
                                              jint max_native_frame);
} // namespace desfire::jni
