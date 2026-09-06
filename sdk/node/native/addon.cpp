/**
 * @file addon.cpp
 * @brief N-API ownership and type boundary over the stable DESFire C ABI.
 *
 * This module runs exclusively inside the package worker. It implements no card
 * framing, cryptography, authentication, or protocol policy.
 */
#include <desfire.h>
#include <node_api.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

    /** @brief Indicate a bridge validation failure without including caller data. */
    class BridgeFailure final : public std::runtime_error {
    public:

        /** @brief Retain a static, non-secret bridge diagnostic. */
        explicit BridgeFailure(const char* message) : std::runtime_error(message) {}
    };

    /** @brief Mark an already installed JavaScript exception. */
    struct PendingException {};

    /** @brief Own a C buffer and release it on all success and exception paths. */
    struct BufferDeleter {
        /** @brief Return an opaque owned buffer to the same ABI that allocated it. */
        void operator()(df_buffer* value) const noexcept {
            df_buffer_free(value);
        }
    };

    using BufferOwner = std::unique_ptr<df_buffer, BufferDeleter>;

    /** @brief Keep worker-local callback references alive for one native card handle. */
    struct Context {
        /** @brief Select the ABI handle family owned by this worker context. */
        enum class Kind { managed, raw };

        napi_env env{};
        napi_ref exchange{};
        napi_ref reset{};
        Kind kind{Kind::managed};
        df_card card{};
        df_raw_channel raw{};
        bool closed{};

        /** @brief Release native ownership and callback roots on every construction/finalization
         * path. */
        ~Context() {
            if (!closed && (card != 0 || raw != 0)) {
                df_error ignored{};
                if (kind == Kind::managed) {
                    df_close(card, &ignored);
                } else {
                    df_raw_close(raw, &ignored);
                }
            }
            if (exchange) {
                napi_delete_reference(env, exchange);
            }
            if (reset) {
                napi_delete_reference(env, reset);
            }
        }
    };

    /** @brief Borrow one JavaScript-owned byte range for a synchronous ABI call. */
    struct Binary {
        const std::uint8_t* data{};
        std::size_t size{};
    };

    /** @brief Own the contiguous ABI records for one transaction plan call. */
    struct TransactionPlan {
        std::vector<df_transaction_operation_v1> values;
    };

    /** @brief Hold one descriptor while its borrowed JavaScript byte ranges remain live. */
    template <class Type> struct Descriptor {
        Type value{};
    };

    /** @brief Convert an N-API status into a bounded bridge exception. */
    void checked(napi_status status) {
        if (status == napi_pending_exception) {
            throw PendingException{};
        }
        if (status != napi_ok) {
            throw BridgeFailure("Invalid native bridge argument or unavailable JavaScript value");
        }
    }

    /** @brief Return JavaScript undefined with N-API status validation. */
    napi_value undefined(napi_env env) {
        napi_value result{};
        checked(napi_get_undefined(env, &result));
        return result;
    }

    /** @brief Read a named field from an object without interpreting it. */
    napi_value property(napi_env env, napi_value object, const char* name) {
        napi_value value{};
        checked(napi_get_named_property(env, object, name, &value));
        return value;
    }

    /** @brief Read one argument from a previously checked JavaScript array. */
    napi_value argument(napi_env env, napi_value values, std::uint32_t index) {
        napi_value value{};
        checked(napi_get_element(env, values, index, &value));
        return value;
    }

    /** @brief Reject missing, additional, or non-array operation arguments. */
    void require_count(napi_env env, napi_value values, std::uint32_t expected) {
        bool is_array{};
        checked(napi_is_array(env, values, &is_array));
        std::uint32_t length{};
        if (!is_array) {
            throw BridgeFailure("Operation arguments must be an array");
        }
        checked(napi_get_array_length(env, values, &length));
        if (length != expected) {
            throw BridgeFailure("Unexpected typed operation argument count");
        }
    }

    /** @brief Read an exact integer without JavaScript's silently narrowing uint32 conversion. */
    double integer(napi_env env, napi_value value, double minimum, double maximum) {
        double number{};
        checked(napi_get_value_double(env, value, &number));
        if (!std::isfinite(number) || std::floor(number) != number || number < minimum ||
            number > maximum) {
            throw BridgeFailure("Numeric argument is outside its exact C ABI integer range");
        }
        return number;
    }

    /** @brief Read an unsigned 32-bit argument after exact range validation. */
    std::uint32_t u32(napi_env env, napi_value value) {
        return static_cast<std::uint32_t>(integer(env, value, 0, 4294967295.0));
    }

    /** @brief Read a signed 32-bit argument after exact range validation. */
    std::int32_t i32(napi_env env, napi_value value) {
        return static_cast<std::int32_t>(integer(env, value, -2147483648.0, 2147483647.0));
    }

    /** @brief Read a Boolean without accepting JavaScript coercion. */
    bool boolean(napi_env env, napi_value value) {
        bool result{};
        checked(napi_get_value_bool(env, value, &result));
        return result;
    }

    /** @brief Return whether an object has its own or inherited named property. */
    bool has_property(napi_env env, napi_value object, const char* name) {
        bool result{};
        checked(napi_has_named_property(env, object, name, &result));
        return result;
    }

    /** @brief Read an optional unsigned property with a caller-selected default. */
    std::uint32_t optional_u32(napi_env env, napi_value object, const char* name,
                               std::uint32_t fallback) {
        return has_property(env, object, name) ? u32(env, property(env, object, name)) : fallback;
    }

    /** @brief Read an optional size property within JavaScript's exact integer range. */
    std::size_t optional_size(napi_env env, napi_value object, const char* name,
                              std::size_t fallback) {
        if (!has_property(env, object, name)) {
            return fallback;
        }
        return static_cast<std::size_t>(
            integer(env, property(env, object, name), 0, 9007199254740991.0));
    }

    /** @brief Borrow only Uint8Array/Buffer data with at most 16 MiB of accessible bytes. */
    Binary binary(napi_env env, napi_value value) {
        napi_typedarray_type kind{};
        std::size_t size{};
        void* data{};
        napi_value storage{};
        std::size_t offset{};
        checked(napi_get_typedarray_info(env, value, &kind, &size, &data, &storage, &offset));
        if (kind != napi_uint8_array || size > 16U * 1024U * 1024U) {
            throw BridgeFailure("Binary argument must be a bounded Uint8Array");
        }
        return {static_cast<const std::uint8_t*>(data), size};
    }

    /** @brief Borrow optional bytes, treating an absent property as an empty range. */
    Binary optional_binary(napi_env env, napi_value object, const char* name) {
        if (!has_property(env, object, name)) {
            return {};
        }
        return binary(env, property(env, object, name));
    }

    /** @brief Decode a short non-secret operation name without truncation. */
    std::string text_argument(napi_env env, napi_value value) {
        char data[96]{};
        std::size_t length{};
        checked(napi_get_value_string_utf8(env, value, nullptr, 0, &length));
        if (length >= sizeof(data)) {
            throw BridgeFailure("Operation name is too long");
        }
        checked(napi_get_value_string_utf8(env, value, data, sizeof(data), &length));
        return {data, length};
    }

    /** @brief Copy one bounded caller string used only for a named cryptographic curve. */
    std::string string_value(napi_env env, napi_value value) {
        std::size_t length{};
        checked(napi_get_value_string_utf8(env, value, nullptr, 0, &length));
        if (length == 0 || length > 128) {
            throw BridgeFailure("String argument length is outside the C ABI bound");
        }
        std::string result(length, '\0');
        std::size_t written{};
        checked(napi_get_value_string_utf8(env, value, result.data(), result.size() + 1, &written));
        result.resize(written);
        return result;
    }

    /** @brief Create a JavaScript number for an exactly representable C integer result. */
    napi_value number_result(napi_env env, double number) {
        napi_value result{};
        checked(napi_create_double(env, number, &result));
        return result;
    }

    /** @brief Create one exact JavaScript Boolean result. */
    napi_value boolean_result(napi_env env, bool value) {
        napi_value result{};
        checked(napi_get_boolean(env, value, &result));
        return result;
    }

    /** @brief Create a fresh JavaScript object. */
    napi_value object_result(napi_env env) {
        napi_value result{};
        checked(napi_create_object(env, &result));
        return result;
    }

    /** @brief Assign numeric error metadata without stringifying payloads. */
    void set_number(napi_env env, napi_value object, const char* name, double value) {
        checked(napi_set_named_property(env, object, name, number_result(env, value)));
    }

    /** @brief Copy fixed bytes into a new JavaScript Buffer property. */
    void set_bytes(napi_env env, napi_value object, const char* name, const std::uint8_t* data,
                   std::size_t size) {
        napi_value bytes{};
        checked(napi_create_buffer_copy(env, size, data, nullptr, &bytes));
        checked(napi_set_named_property(env, object, name, bytes));
    }

    /** @brief Initialize the common header of a version-one C ABI output descriptor. */
    template <class Type> void initialize_descriptor(Type& value) {
        value.struct_size = sizeof(Type);
        value.abi_version = DF_ABI_VERSION;
    }

    /** @brief Throw native status and per-call delivery evidence as a JavaScript Error. */
    void check_native(napi_env env, std::int32_t status, const df_error& error) {
        if (status == DF_OK) {
            return;
        }
        napi_value message{};
        napi_value exception{};
        checked(napi_create_string_utf8(env, error.message, NAPI_AUTO_LENGTH, &message));
        checked(napi_create_error(env, nullptr, message, &exception));
        set_number(env, exception, "code", status);
        set_number(env, exception, "outcome", error.outcome);
        set_number(env, exception, "deviceStatus", error.device_status);
        checked(napi_throw(env, exception));
        throw PendingException{};
    }

    /** @brief Copy a C-owned output before its RAII owner releases the native allocation. */
    napi_value buffer_result(napi_env env, const df_buffer* output) {
        napi_value result{};
        const std::size_t size = df_buffer_size(output);
        checked(napi_create_buffer_copy(env, size, df_buffer_data(output), nullptr, &result));
        return result;
    }

    /** @brief Return verified EV2 public authentication metadata as owned byte arrays. */
    napi_value authentication_result(napi_env env, const df_authentication_info_v1& value) {
        auto result = object_result(env);
        set_bytes(env, result, "transactionIdentifier", value.transaction_identifier,
                  sizeof(value.transaction_identifier));
        set_bytes(env, result, "piccCapabilities", value.picc_capabilities,
                  sizeof(value.picc_capabilities));
        set_bytes(env, result, "pcdCapabilities", value.pcd_capabilities,
                  sizeof(value.pcd_capabilities));
        return result;
    }

    /** @brief Return one delegated-application record with exact scalar widths. */
    napi_value delegated_result(napi_env env, const df_delegated_application_info_v1& value) {
        auto result = object_result(env);
        set_number(env, result, "slotVersion", value.slot_version);
        set_number(env, result, "quotaLimit", value.quota_limit);
        set_number(env, result, "freeBlocks", value.free_blocks);
        set_number(env, result, "applicationId", value.application_id);
        return result;
    }

    /** @brief Preserve native or ISO status alongside an owned response buffer. */
    napi_value status_response(napi_env env, std::uint32_t status, const df_buffer* output) {
        auto result = object_result(env);
        set_number(env, result, "status", status);
        checked(napi_set_named_property(env, result, "data", buffer_result(env, output)));
        return result;
    }

    /** @brief Convert named PICC settings to one initialized ABI descriptor. */
    Descriptor<df_picc_configuration_v1> picc_configuration(napi_env env, napi_value object) {
        Descriptor<df_picc_configuration_v1> result{};
        initialize_descriptor(result.value);
        const auto flag = [&](const char* name) -> std::uint32_t {
            return has_property(env, object, name) && boolean(env, property(env, object, name));
        };
        result.value.disable_format = flag("disableFormat");
        result.value.random_identifier = flag("randomIdentifier");
        result.value.proximity_check_mandatory = flag("proximityCheckMandatory");
        result.value.virtual_card_authentication_mandatory =
            flag("virtualCardAuthenticationMandatory");
        result.value.error_code_binding = flag("errorCodeBinding");
        result.value.random_identifier_configuration = flag("randomIdentifierConfiguration");
        result.value.four_byte_nuid_configuration = flag("fourByteNuidConfiguration");
        return result;
    }

    /** @brief Convert all delegated-application MAC fields into one versioned descriptor. */
    Descriptor<df_delegated_application_configuration_v1>
    delegated_application_configuration(napi_env env, napi_value object) {
        Descriptor<df_delegated_application_configuration_v1> result{};
        initialize_descriptor(result.value);
        result.value.application_id = u32(env, property(env, object, "applicationId"));
        result.value.key_settings = u32(env, property(env, object, "keySettings"));
        result.value.number_of_keys = u32(env, property(env, object, "numberOfKeys"));
        result.value.slot = u32(env, property(env, object, "slot"));
        result.value.slot_version = u32(env, property(env, object, "slotVersion"));
        result.value.quota_limit = u32(env, property(env, object, "quotaLimit"));
        result.value.iso_file_identifiers =
            has_property(env, object, "isoFileIdentifiers") &&
            boolean(env, property(env, object, "isoFileIdentifiers"));
        result.value.key_settings3 = has_property(env, object, "keySettings3")
                                         ? i32(env, property(env, object, "keySettings3"))
                                         : -1;
        result.value.iso_id =
            has_property(env, object, "isoId") ? i32(env, property(env, object, "isoId")) : -1;
        const auto name = optional_binary(env, object, "dfName");
        result.value.df_name = name.data;
        result.value.df_name_size = name.size;
        result.value.has_key_sets = has_property(env, object, "numberOfKeySets");
        result.value.active_key_set_version = optional_u32(env, object, "activeKeySetVersion", 0);
        result.value.number_of_key_sets = optional_u32(env, object, "numberOfKeySets", 0);
        result.value.maximum_key_size = optional_u32(env, object, "maximumKeySize", 0);
        result.value.key_set_settings = optional_u32(env, object, "keySetSettings", 0);
        return result;
    }

    /** @brief Convert one JavaScript transaction array into contiguous initialized records. */
    TransactionPlan transaction_plan(napi_env env, napi_value array) {
        bool is_array{};
        checked(napi_is_array(env, array, &is_array));
        std::uint32_t count{};
        checked(napi_get_array_length(env, array, &count));
        if (!is_array || count == 0 || count > 65536) {
            throw BridgeFailure("Transaction plan must be a bounded non-empty array");
        }
        TransactionPlan result;
        result.values.reserve(count);
        for (std::uint32_t index = 0; index < count; ++index) {
            const auto object = argument(env, array, index);
            df_transaction_operation_v1 operation{};
            initialize_descriptor(operation);
            operation.kind = u32(env, property(env, object, "kind"));
            operation.file = u32(env, property(env, object, "file"));
            operation.communication = u32(env, property(env, object, "communication"));
            operation.offset = optional_u32(env, object, "offset", 0);
            operation.record = optional_u32(env, object, "record", 0);
            operation.amount = optional_u32(env, object, "amount", 0);
            const auto data = optional_binary(env, object, "data");
            operation.data = data.data;
            operation.data_size = data.size;
            result.values.push_back(operation);
        }
        return result;
    }

    /** @brief Convert one explicit native logical request without inferring command semantics. */
    Descriptor<df_native_request_v1> native_request(napi_env env, napi_value object) {
        Descriptor<df_native_request_v1> result{};
        initialize_descriptor(result.value);
        result.value.framing = u32(env, property(env, object, "framing"));
        result.value.command = u32(env, property(env, object, "command"));
        const auto data = optional_binary(env, object, "data");
        result.value.data = data.data;
        result.value.data_size = data.size;
        result.value.maximum_response = optional_size(env, object, "maximumResponse", 4096);
        result.value.first_frame_data_size =
            optional_size(env, object, "firstFrameDataSize", DF_RAW_NO_FIRST_FRAME_BOUNDARY);
        result.value.flags = optional_u32(env, object, "flags", 0);
        return result;
    }

    /** @brief Convert one secure-native request whose header and data boundaries are explicit. */
    Descriptor<df_native_secure_request_v1> native_secure_request(napi_env env, napi_value object) {
        Descriptor<df_native_secure_request_v1> result{};
        initialize_descriptor(result.value);
        result.value.profile = u32(env, property(env, object, "profile"));
        result.value.command = u32(env, property(env, object, "command"));
        const auto header = optional_binary(env, object, "header");
        const auto data = optional_binary(env, object, "data");
        result.value.header = header.data;
        result.value.header_size = header.size;
        result.value.data = data.data;
        result.value.data_size = data.size;
        result.value.request_communication =
            u32(env, property(env, object, "requestCommunication"));
        result.value.response_communication =
            u32(env, property(env, object, "responseCommunication"));
        result.value.minimum_response = optional_size(env, object, "minimumResponse", 0);
        result.value.maximum_response = optional_size(env, object, "maximumResponse", 4096);
        result.value.first_frame_data_size =
            optional_size(env, object, "firstFrameDataSize", DF_RAW_NO_FIRST_FRAME_BOUNDARY);
        result.value.flags = optional_u32(env, object, "flags", 0);
        result.value.invalidates_session =
            has_property(env, object, "invalidatesSession") &&
            boolean(env, property(env, object, "invalidatesSession"));
        return result;
    }

    /** @brief Convert one full ISO APDU descriptor and preserve explicit length policy. */
    Descriptor<df_iso_apdu_v1> iso_apdu(napi_env env, napi_value object) {
        Descriptor<df_iso_apdu_v1> result{};
        initialize_descriptor(result.value);
        result.value.cla = u32(env, property(env, object, "cla"));
        result.value.ins = u32(env, property(env, object, "ins"));
        result.value.p1 = u32(env, property(env, object, "p1"));
        result.value.p2 = u32(env, property(env, object, "p2"));
        const auto data = optional_binary(env, object, "data");
        result.value.data = data.data;
        result.value.data_size = data.size;
        result.value.has_le = has_property(env, object, "le");
        result.value.le = optional_u32(env, object, "le", 0);
        result.value.length_encoding = optional_u32(env, object, "lengthEncoding", 0);
        result.value.correct_length = has_property(env, object, "correctLength") &&
                                      boolean(env, property(env, object, "correctLength"));
        result.value.maximum_response = optional_size(env, object, "maximumResponse", 4096);
        result.value.maximum_frames = optional_size(env, object, "maximumFrames", 32);
        return result;
    }

    /** @brief Resolve a worker-local external context and reject closed sessions. */
    Context& card_context(napi_env env, napi_value value) {
        void* pointer{};
        checked(napi_get_value_external(env, value, &pointer));
        if (!pointer) {
            throw BridgeFailure("Missing native card context");
        }
        auto& context = *static_cast<Context*>(pointer);
        if (context.closed || context.env != env) {
            throw BridgeFailure("Card is closed or belongs to another JavaScript environment");
        }
        return context;
    }

    /** @brief Call the worker's synchronous rendezvous callback using the same N-API environment.
     */
    napi_value callback(Context& context, napi_ref reference, std::size_t count,
                        napi_value* arguments) {
        napi_value function{};
        napi_value result{};
        checked(napi_get_reference_value(context.env, reference, &function));
        checked(napi_call_function(context.env, undefined(context.env), function, count, arguments,
                                   &result));
        return result;
    }

    /** @brief Decode redacted failure evidence supplied by the JavaScript reader bridge. */
    std::int32_t callback_status(napi_env env, napi_value response, df_error* error) {
        const std::uint32_t code = u32(env, property(env, response, "code"));
        if (code == DF_OK) {
            return DF_OK;
        }
        const std::uint32_t outcome = u32(env, property(env, response, "outcome"));
        const std::uint32_t status = u32(env, property(env, response, "deviceStatus"));
        error->code = DF_TRANSPORT;
        error->outcome = DF_UNKNOWN;
        if (code <= DF_INTERNAL) {
            error->code = code;
        }
        if (outcome <= DF_UNKNOWN) {
            error->outcome = outcome;
        }
        if (status <= 65535) {
            error->device_status = static_cast<std::uint16_t>(status);
        }
        std::strcpy(error->message, "Reader callback failed");
        return static_cast<std::int32_t>(error->code);
    }

    /** @brief Contain any bridge failure before returning through a C transport callback. */
    std::int32_t callback_failure(napi_env env, df_error* error) noexcept {
        bool pending{};
        napi_is_exception_pending(env, &pending);
        if (pending) {
            napi_value ignored{};
            napi_get_and_clear_last_exception(env, &ignored);
        }
        *error = {};
        error->code = DF_TRANSPORT;
        error->outcome = DF_UNKNOWN;
        std::strcpy(error->message, "JavaScript reader bridge failed");
        return DF_TRANSPORT;
    }

    /** @brief Perform one physical reader exchange; no callback or command is retried. */
    std::int32_t exchange(void* pointer, const std::uint8_t* transmit, std::size_t transmit_size,
                          std::uint8_t* receive, std::size_t capacity, std::size_t* received,
                          std::uint32_t timeout, df_error* error) noexcept {
        auto& context = *static_cast<Context*>(pointer);
        *received = 0;
        napi_handle_scope scope{};
        try {
            checked(napi_open_handle_scope(context.env, &scope));
            napi_value arguments[3]{};
            checked(napi_create_buffer_copy(context.env, transmit_size, transmit, nullptr,
                                            &arguments[0]));
            arguments[1] = number_result(context.env, timeout);
            arguments[2] = number_result(context.env, static_cast<double>(capacity));
            const auto response = callback(context, context.exchange, 3, arguments);
            const auto status = callback_status(context.env, response, error);
            if (status == DF_OK) {
                const auto bytes = binary(context.env, property(context.env, response, "data"));
                if (bytes.size > capacity) {
                    throw BridgeFailure("Reader response exceeds declared capacity");
                }
                if (bytes.size != 0) {
                    std::memcpy(receive, bytes.data, bytes.size);
                }
                *received = bytes.size;
            }
            checked(napi_close_handle_scope(context.env, scope));
            return status;
        } catch (...) {
            if (scope) {
                napi_close_handle_scope(context.env, scope);
            }
            return callback_failure(context.env, error);
        }
    }

    /** @brief Perform a requested reset through the reader's worker rendezvous callback. */
    std::int32_t reset(void* pointer, df_error* error) noexcept {
        auto& context = *static_cast<Context*>(pointer);
        try {
            const auto response = callback(context, context.reset, 0, nullptr);
            return callback_status(context.env, response, error);
        } catch (...) {
            return callback_failure(context.env, error);
        }
    }

    /** @brief Close the native card and delete callback roots after external ownership ends. */
    void finalize(napi_env env, void* pointer, void*) noexcept {
        static_cast<void>(env);
        delete static_cast<Context*>(pointer);
    }

    /** @brief Contain all C++ exceptions at a JavaScript entry boundary. */
    template <class Function> napi_value boundary(napi_env env, Function function) noexcept {
        try {
            return function();
        } catch (const PendingException&) {
            return nullptr;
        } catch (const BridgeFailure& failure) {
            napi_throw_type_error(env, nullptr, failure.what());
            return nullptr;
        } catch (...) {
            napi_throw_error(env, nullptr, "Native JavaScript bridge failed");
            return nullptr;
        }
    }

    /** @brief Open a managed or raw channel with worker-owned transport callbacks. */
    napi_value open_context(napi_env env, napi_callback_info info, Context::Kind kind) {
        return boundary(env, [&]() {
            if (df_abi_version() != DF_ABI_VERSION) {
                throw BridgeFailure("Native DESFire library ABI version is incompatible");
            }
            napi_value arguments[3]{};
            std::size_t argument_count = 3;
            checked(napi_get_cb_info(env, info, &argument_count, arguments, nullptr, nullptr));
            if (argument_count != 3) {
                throw BridgeFailure("Open requires exchange, reset, and transport options");
            }
            auto context = std::make_unique<Context>();
            context->env = env;
            context->kind = kind;
            checked(napi_create_reference(env, arguments[0], 1, &context->exchange));
            napi_valuetype reset_type{};
            checked(napi_typeof(env, arguments[1], &reset_type));
            df_transport transport{};
            transport.struct_size = sizeof(transport);
            transport.abi_version = DF_ABI_VERSION;
            transport.framing = u32(env, property(env, arguments[2], "framing"));
            transport.max_transmit = u32(env, property(env, arguments[2], "maxTransmit"));
            transport.max_receive = u32(env, property(env, arguments[2], "maxReceive"));
            transport.max_native_frame = u32(env, property(env, arguments[2], "maxNativeFrame"));
            transport.context = context.get();
            transport.exchange = exchange;
            if (reset_type == napi_function) {
                checked(napi_create_reference(env, arguments[1], 1, &context->reset));
                transport.reset = reset;
            }
            df_error error{};
            const auto status = kind == Context::Kind::managed
                                    ? df_open(&transport, &context->card, &error)
                                    : df_raw_open(&transport, &context->raw, &error);
            if (status != DF_OK) {
                finalize(env, context.release(), nullptr);
                check_native(env, status, error);
            }
            napi_value result{};
            checked(napi_create_external(env, context.get(), finalize, nullptr, &result));
            context.release();
            return result;
        });
    }

    /** @brief Open one managed Card context. */
    napi_value open(napi_env env, napi_callback_info info) {
        return open_context(env, info, Context::Kind::managed);
    }

    /** @brief Open one independent raw-channel context. */
    napi_value raw_open(napi_env env, napi_callback_info info) {
        return open_context(env, info, Context::Kind::raw);
    }

#include "dispatch.inc"

    /** @brief Dispatch one named typed C ABI operation synchronously on the package worker. */
    napi_value invoke(napi_env env, napi_callback_info info) {
        return boundary(env, [&]() {
            napi_value inputs[3]{};
            std::size_t argument_count = 3;
            checked(napi_get_cb_info(env, info, &argument_count, inputs, nullptr, nullptr));
            if (argument_count != 3) {
                throw BridgeFailure("Invoke requires a card, operation name, and arguments");
            }
            Context& context = card_context(env, inputs[0]);
            const auto operation = text_argument(env, inputs[1]);
            const auto arguments = inputs[2];
            df_error error{};
            if (context.kind == Context::Kind::managed && operation == "df_reset") {
                require_count(env, arguments, 0);
                check_native(env, df_reset(context.card, &error), error);
                return undefined(env);
            }
            if (context.kind == Context::Kind::managed && operation == "df_notify_state_change") {
                require_count(env, arguments, 0);
                check_native(env, df_notify_state_change(context.card, &error), error);
                return undefined(env);
            }
            if (context.kind == Context::Kind::raw && operation == "df_raw_reset") {
                require_count(env, arguments, 0);
                check_native(env, df_raw_reset(context.raw, &error), error);
                return undefined(env);
            }
            if (context.kind == Context::Kind::raw && operation == "df_raw_notify_state_change") {
                require_count(env, arguments, 0);
                check_native(env, df_raw_notify_state_change(context.raw, &error), error);
                return undefined(env);
            }
            return context.kind == Context::Kind::managed
                       ? dispatch_managed(env, context, operation, arguments)
                       : dispatch_raw(env, context, operation, arguments);
        });
    }

    /** @brief Dispatch one stateless offline C ABI operation on the package worker. */
    napi_value invoke_offline(napi_env env, napi_callback_info info) {
        return boundary(env, [&]() {
            napi_value inputs[2]{};
            std::size_t argument_count = 2;
            checked(napi_get_cb_info(env, info, &argument_count, inputs, nullptr, nullptr));
            if (argument_count != 2) {
                throw BridgeFailure("Offline invoke requires an operation name and arguments");
            }
            return dispatch_offline(env, text_argument(env, inputs[0]), inputs[1]);
        });
    }

    /** @brief Explicitly close a worker-local native handle while retaining safe stale ownership.
     */
    napi_value close(napi_env env, napi_callback_info info) {
        return boundary(env, [&]() {
            napi_value value{};
            std::size_t count = 1;
            checked(napi_get_cb_info(env, info, &count, &value, nullptr, nullptr));
            Context& context = card_context(env, value);
            df_error error{};
            const auto status = context.kind == Context::Kind::managed
                                    ? df_close(context.card, &error)
                                    : df_raw_close(context.raw, &error);
            check_native(env, status, error);
            context.closed = true;
            return undefined(env);
        });
    }

    /** @brief Return the canonical API-manifest digest embedded in the linked C ABI. */
    napi_value manifest_hash(napi_env env, napi_callback_info info) {
        return boundary(env, [&]() {
            std::size_t count = 0;
            checked(napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr));
            if (count != 0) {
                throw BridgeFailure("manifestHash accepts no arguments");
            }
            napi_value result{};
            checked(napi_create_string_utf8(env, df_manifest_sha256(), NAPI_AUTO_LENGTH, &result));
            return result;
        });
    }

    /** @brief Export the minimal ownership bridge; typed operations are generated in JavaScript. */
    napi_value initialize(napi_env env, napi_value exports) {
        return boundary(env, [&]() {
            const napi_property_descriptor descriptors[]{
                {"open", nullptr, open, nullptr, nullptr, nullptr, napi_default, nullptr},
                {"rawOpen", nullptr, raw_open, nullptr, nullptr, nullptr, napi_default, nullptr},
                {"invoke", nullptr, invoke, nullptr, nullptr, nullptr, napi_default, nullptr},
                {"invokeOffline", nullptr, invoke_offline, nullptr, nullptr, nullptr, napi_default,
                 nullptr},
                {"close", nullptr, close, nullptr, nullptr, nullptr, napi_default, nullptr},
                {"manifestHash", nullptr, manifest_hash, nullptr, nullptr, nullptr, napi_default,
                 nullptr}};
            checked(napi_define_properties(env, exports, 6, descriptors));
            return exports;
        });
    }

} // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
