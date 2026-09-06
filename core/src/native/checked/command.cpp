/**
 * @file command.cpp
 * @brief Ownership operations for immutable checked native commands.
 */
#include "detail/command_support.hpp"

namespace desfire::ev3::native::checked {

    using model::CommunicationMode;

    /** @brief Seal one fully validated internal builder into an immutable command. */
    Command::Command(detail::CommandBuilder&& builder) noexcept
        : opcode_(builder.opcode), header_(std::move(builder.header)),
          data_(std::move(builder.data)), request_mode_(builder.request_mode),
          response_mode_(builder.response_mode), minimum_response_(builder.minimum_response),
          maximum_response_(builder.maximum_response),
          requires_authentication_(builder.requires_authentication),
          requires_ev2_session_(builder.requires_ev2_session),
          requires_picc_selection_(builder.requires_picc_selection),
          requires_single_continuation_frame_(builder.requires_single_continuation_frame),
          invalidates_session_(builder.invalidates_session),
          current_authenticated_key_(builder.current_authenticated_key),
          allowed_authenticated_keys_(builder.allowed_authenticated_keys),
          first_frame_payload_size_(builder.first_frame_payload_size), valid_(true) {}

    /** @brief Transfer validated command ownership and invalidate the source object. */
    Command::Command(Command&& other) noexcept
        : opcode_(other.opcode_), header_(std::move(other.header_)), data_(std::move(other.data_)),
          request_mode_(other.request_mode_), response_mode_(other.response_mode_),
          minimum_response_(other.minimum_response_), maximum_response_(other.maximum_response_),
          requires_authentication_(other.requires_authentication_),
          requires_ev2_session_(other.requires_ev2_session_),
          requires_picc_selection_(other.requires_picc_selection_),
          requires_single_continuation_frame_(other.requires_single_continuation_frame_),
          invalidates_session_(other.invalidates_session_),
          current_authenticated_key_(other.current_authenticated_key_),
          allowed_authenticated_keys_(other.allowed_authenticated_keys_),
          first_frame_payload_size_(other.first_frame_payload_size_), valid_(other.valid_) {
        other.valid_ = false;
    }

    /** @brief Replace command ownership and invalidate the source object. */
    Command& Command::operator=(Command&& other) noexcept {
        if (this != &other) {
            opcode_ = other.opcode_;
            header_ = std::move(other.header_);
            data_ = std::move(other.data_);
            request_mode_ = other.request_mode_;
            response_mode_ = other.response_mode_;
            minimum_response_ = other.minimum_response_;
            maximum_response_ = other.maximum_response_;
            requires_authentication_ = other.requires_authentication_;
            requires_ev2_session_ = other.requires_ev2_session_;
            requires_picc_selection_ = other.requires_picc_selection_;
            requires_single_continuation_frame_ = other.requires_single_continuation_frame_;
            invalidates_session_ = other.invalidates_session_;
            current_authenticated_key_ = other.current_authenticated_key_;
            allowed_authenticated_keys_ = other.allowed_authenticated_keys_;
            first_frame_payload_size_ = other.first_frame_payload_size_;
            valid_ = other.valid_;
            other.valid_ = false;
        }
        return *this;
    }

} // namespace desfire::ev3::native::checked
