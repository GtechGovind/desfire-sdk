/**
 * @file transactions.cpp
 * @brief Checked native transaction-command construction and response decoding.
 */
#include "detail/command_support.hpp"
#include <desfire/ev3/native/checked/transactions.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <set>

namespace desfire::ev3::native::checked {

    using namespace detail;

    /** @brief Implement `parse_value` to decode an exact signed value-file response. */
    Result<std::int32_t> parse_value(ByteView payload) {
        if (payload.size() != 4) {
            return malformed("EV3 value response requires four bytes");
        }
        return std::bit_cast<std::int32_t>(get_le(payload));
    }

    /** @brief Implement `parse_transaction_mac` to decode an exact counter-and-MAC response. */
    Result<TransactionMac> parse_transaction_mac(ByteView payload) {
        if (payload.size() != 12) {
            return malformed("EV3 transaction MAC requires a counter and eight MAC bytes");
        }
        TransactionMac transaction{get_le(payload.first(4)), {}};
        std::copy(payload.begin() + 4, payload.end(), transaction.mac.begin());
        return transaction;
    }

    /** @brief Implement `get_value` to build protected value-file retrieval. */
    Result<Command> get_value(model::FileNumber file, model::CommunicationMode mode) {
        return file_command(0x6C, {static_cast<Byte>(file.value())}, {}, mode, true, 4, 4);
    }

    /** @brief Implement `credit` to build transactional value credit. */
    Result<Command> credit(model::FileNumber file, std::uint32_t amount,
                           model::CommunicationMode mode) {
        return value_change(0x0C, file, amount, mode);
    }

    /** @brief Implement `debit` to build transactional value debit. */
    Result<Command> debit(model::FileNumber file, std::uint32_t amount,
                          model::CommunicationMode mode) {
        return value_change(0xDC, file, amount, mode);
    }

    /** @brief Implement `limited_credit` to build transactional limited credit. */
    Result<Command> limited_credit(model::FileNumber file, std::uint32_t amount,
                                   model::CommunicationMode mode) {
        return value_change(0x1C, file, amount, mode);
    }

    /** @brief Implement `restore_transfer` to build transactional value restoration. */
    Result<Command> restore_transfer(model::FileNumber target, model::FileNumber source,
                                     model::CommunicationMode mode) {
        if (mode != model::CommunicationMode::plain && mode != model::CommunicationMode::mac) {
            return invalid("RestoreTransfer supports only Plain or MAC communication");
        }
        const std::array<Byte, 2> data{static_cast<Byte>(target.value()),
                                       static_cast<Byte>(source.value())};
        return file_command(0xB1, {}, data, mode, false);
    }

    /** @brief Implement `commit_transaction` to build transaction commit with optional MAC
     * response. */
    Result<Command> commit_transaction(bool return_transaction_mac) {
        if (return_transaction_mac) {
            return management(0xC7, {0x01}, 12, 12).build();
        }
        return management(0xC7).build();
    }

    /** @brief Implement `abort_transaction` to build transaction abort. */
    Result<Command> abort_transaction() {
        return management(0xA7).build();
    }

    /** @brief Implement `commit_reader_id` to build reader-identifier commit. */
    Result<Command> commit_reader_id(ByteView reader_id) {
        if (reader_id.size() != 16) {
            return invalid("CommitReaderID requires a sixteen-byte reader identifier");
        }
        detail::CommandBuilder command =
            management(0xC8, Bytes(reader_id.begin(), reader_id.end()), 16, 16);
        command.requires_authentication = true;
        return command.build();
    }

} // namespace desfire::ev3::native::checked
