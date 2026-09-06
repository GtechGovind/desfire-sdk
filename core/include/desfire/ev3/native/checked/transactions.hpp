/**
 * @file transactions.hpp
 * @brief Checked DESFire EV3 value and transaction-management commands.
 */
#pragma once

#include "command.hpp"
#include <desfire/ev3/model/identifiers.hpp>

#include <array>

namespace desfire::ev3::native::checked {

    /** @brief Parsed committed transaction counter and eight-byte transaction MAC. */
    struct TransactionMac final {
        std::uint32_t counter{};   ///< Four-byte little-endian committed counter.
        std::array<Byte, 8> mac{}; ///< Eight-byte transaction MAC.
    };

    /**
     * @brief Decode exactly four counter bytes followed by eight transaction-MAC bytes.
     * @param payload Exact twelve-byte status-free response.
     * @return Parsed counter and MAC or malformed_response.
     */
    Result<TransactionMac> parse_transaction_mac(ByteView payload);

    /**
     * @brief Decode exactly four little-endian two's-complement value bytes.
     * @param payload Exact four-byte status-free response.
     * @return Signed value or malformed_response.
     */
    Result<std::int32_t> parse_value(ByteView payload);

    /** @brief Build a value-file read under the selected communication mode. */
    Result<Command> get_value(model::FileNumber file, model::CommunicationMode communication);

    /** @brief Build a transactional credit. */
    Result<Command> credit(model::FileNumber file, std::uint32_t amount,
                           model::CommunicationMode communication);

    /** @brief Build a transactional debit. */
    Result<Command> debit(model::FileNumber file, std::uint32_t amount,
                          model::CommunicationMode communication);

    /** @brief Build a transactional limited credit. */
    Result<Command> limited_credit(model::FileNumber file, std::uint32_t amount,
                                   model::CommunicationMode communication);

    /**
     * @brief Build MIFARE Classic RestoreTransfer between two value files.
     * @param target Target DESFire value file.
     * @param source Source DESFire value file.
     * @param communication Plain or MAC command communication.
     * @return Checked transactional command or pre-I/O validation failure.
     */
    Result<Command> restore_transfer(model::FileNumber target, model::FileNumber source,
                                     model::CommunicationMode communication);

    /** @brief Build explicit transaction commit with an optional transaction-MAC receipt. */
    Result<Command> commit_transaction(bool return_transaction_mac = false);

    /** @brief Build explicit transaction abort. */
    Result<Command> abort_transaction();

    /** @brief Build CommitReaderID using exactly sixteen caller-supplied bytes. */
    Result<Command> commit_reader_id(ByteView reader_id);

} // namespace desfire::ev3::native::checked
