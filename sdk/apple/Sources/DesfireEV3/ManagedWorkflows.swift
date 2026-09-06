import CDesfire
import Foundation

/** Parsed delegated-application slot information. */
public struct DelegatedApplicationInfo: Sendable, Equatable {
    public let slotVersion: UInt8
    public let quotaLimit: UInt16
    public let freeBlocks: UInt16
    public let applicationId: ApplicationId
}

/** Named SetConfiguration option-zero flags. */
public struct PiccConfiguration: Sendable {
    public var disableFormat = false
    public var randomIdentifier = false
    public var proximityCheckMandatory = false
    public var virtualCardAuthenticationMandatory = false
    public var errorCodeBinding = false
    public var randomIdentifierConfiguration = false
    public var fourByteNuidConfiguration = false

    /** Construct one explicit option-zero configuration. */
    public init() {}
}

/** One checked mutation accepted by a managed atomic transaction plan. */
public enum TransactionMutation: Sendable {
    case writeData(file: FileNumber, offset: UInt32, data: Data, mode: CommunicationMode)
    case credit(file: FileNumber, amount: UInt32, mode: CommunicationMode)
    case debit(file: FileNumber, amount: UInt32, mode: CommunicationMode)
    case limitedCredit(file: FileNumber, amount: UInt32, mode: CommunicationMode)
    case writeRecord(file: FileNumber, offset: UInt32, data: Data, mode: CommunicationMode)
    case updateRecord(
        file: FileNumber, record: UInt32, offset: UInt32, data: Data,
        mode: CommunicationMode)
    case clearRecordFile(file: FileNumber)
}

extension Card {
    /** Read and parse one delegated-application slot. */
    public func delegatedApplicationInfo(
        slot: UInt16, timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> DelegatedApplicationInfo {
        try await perform { handle in
            var native = df_delegated_application_info_v1()
            native.struct_size = UInt32(MemoryLayout.size(ofValue: native))
            native.abi_version = 1
            var error = df_error()
            try checkNative(
                df_get_delegated_application_info(
                    handle, UInt32(slot), timeoutMilliseconds, &native, &error), error)
            guard native.slot_version <= 0xFF, native.quota_limit <= 0xFFFF,
                native.free_blocks <= 0xFFFF,
                let application = ApplicationId(rawValue: native.application_id)
            else {
                throw DesfireError(
                    .malformedResponse, "Native delegated-application result is invalid",
                    outcome: .succeeded)
            }
            return DelegatedApplicationInfo(
                slotVersion: UInt8(native.slot_version), quotaLimit: UInt16(native.quota_limit),
                freeBlocks: UInt16(native.free_blocks), applicationId: application)
        }
    }

    /** Apply named PICC option-zero configuration flags. */
    public func setPiccConfiguration(
        _ configuration: PiccConfiguration, timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        try await perform { handle in
            var native = df_picc_configuration_v1()
            native.struct_size = UInt32(MemoryLayout.size(ofValue: native))
            native.abi_version = 1
            native.disable_format = configuration.disableFormat ? 1 : 0
            native.random_identifier = configuration.randomIdentifier ? 1 : 0
            native.proximity_check_mandatory = configuration.proximityCheckMandatory ? 1 : 0
            native.virtual_card_authentication_mandatory =
                configuration.virtualCardAuthenticationMandatory ? 1 : 0
            native.error_code_binding = configuration.errorCodeBinding ? 1 : 0
            native.random_identifier_configuration =
                configuration.randomIdentifierConfiguration ? 1 : 0
            native.four_byte_nuid_configuration = configuration.fourByteNuidConfiguration ? 1 : 0
            var error = df_error()
            try checkNative(
                df_set_picc_configuration(handle, &native, timeoutMilliseconds, &error), error)
        }
    }

    /** Execute one through 128 checked mutations and commit them under one card admission. */
    public func executeTransaction(
        _ operations: [TransactionMutation], returnMac: Bool = false,
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> Data {
        guard !operations.isEmpty, operations.count <= 128 else {
            throw DesfireError(.invalidArgument, "Transaction requires one through 128 mutations")
        }
        return try await perform { handle in
            let owners: [NSData] = operations.map { operation in
                switch operation {
                case .writeData(_, _, let data, _), .writeRecord(_, _, let data, _),
                    .updateRecord(_, _, _, let data, _):
                    return data as NSData
                default:
                    return NSData()
                }
            }
            var native = operations.enumerated().map { index, operation in
                var value = df_transaction_operation_v1()
                value.struct_size = UInt32(MemoryLayout.size(ofValue: value))
                value.abi_version = 1
                switch operation {
                case .writeData(let file, let offset, let data, let mode):
                    value.kind = 1
                    value.file = UInt32(file.rawValue)
                    value.communication = mode.rawValue
                    value.offset = offset
                    value.data = owners[index].bytes.assumingMemoryBound(to: UInt8.self)
                    value.data_size = data.count
                case .credit(let file, let amount, let mode):
                    value.kind = 2
                    value.file = UInt32(file.rawValue)
                    value.communication = mode.rawValue
                    value.amount = amount
                case .debit(let file, let amount, let mode):
                    value.kind = 3
                    value.file = UInt32(file.rawValue)
                    value.communication = mode.rawValue
                    value.amount = amount
                case .limitedCredit(let file, let amount, let mode):
                    value.kind = 4
                    value.file = UInt32(file.rawValue)
                    value.communication = mode.rawValue
                    value.amount = amount
                case .writeRecord(let file, let offset, let data, let mode):
                    value.kind = 5
                    value.file = UInt32(file.rawValue)
                    value.communication = mode.rawValue
                    value.offset = offset
                    value.data = owners[index].bytes.assumingMemoryBound(to: UInt8.self)
                    value.data_size = data.count
                case .updateRecord(let file, let record, let offset, let data, let mode):
                    value.kind = 6
                    value.file = UInt32(file.rawValue)
                    value.communication = mode.rawValue
                    value.offset = offset
                    value.record = record
                    value.data = owners[index].bytes.assumingMemoryBound(to: UInt8.self)
                    value.data_size = data.count
                case .clearRecordFile(let file):
                    value.kind = 7
                    value.file = UInt32(file.rawValue)
                    value.communication = CommunicationMode.plain.rawValue
                }
                return value
            }
            var error = df_error()
            var output: OpaquePointer?
            defer { df_buffer_free(output) }
            try checkNative(
                df_execute_transaction(
                    handle, &native, native.count, returnMac ? 1 : 0, timeoutMilliseconds,
                    &output, &error), error)
            return try ownedBuffer(output)
        }
    }

    /** Set the default application AES key after resolving it within this card's FIFO queue. */
    public func setDefaultAesKey(
        _ source: KeySource, keyVersion: UInt8, timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        guard let number = KeyNumber(rawValue: 0) else {
            throw DesfireError(.internal, "Invalid built-in default-key selector")
        }
        try await performWithKeySource(
            source, keyNumber: number, profile: nil, scope: .native,
            purpose: .replacementKey
        ) { handle, key in
            try withBinary(key) { pointer, count in
                var error = df_error()
                try checkNative(
                    df_set_default_aes_key(
                        handle, pointer, count, UInt32(keyVersion), timeoutMilliseconds, &error),
                    error)
            }
        }
    }

    /** Create a transaction-MAC file after resolving its file key before the first card frame. */
    public func createTransactionMacFile(
        file: FileNumber, accessRights: UInt16, keyNumber: KeyNumber, key: KeySource,
        keyVersion: UInt8,
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        try await performWithKeySource(
            key, keyNumber: keyNumber, profile: nil, scope: .native,
            purpose: .transactionMac
        ) { handle, resolved in
            try withBinary(resolved) { pointer, count in
                var error = df_error()
                try checkNative(
                    df_create_transaction_mac_file(
                        handle, UInt32(file.rawValue), UInt32(accessRights), pointer, count,
                        UInt32(keyVersion), timeoutMilliseconds, &error), error)
            }
        }
    }

    /** Resolve replacement and optional current AES keys before one ChangeKey command. */
    public func changeAesKey(
        number: KeyNumber, replacement: KeySource, version: UInt8,
        authenticatedKey: KeyNumber, current: KeySource? = nil, keySet: UInt8? = nil,
        piccMaster: Bool = false, timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        guard keySet == nil || keySet! <= 15 else {
            throw DesfireError(.invalidArgument, "Key set must be zero through fifteen")
        }
        try await performWithKeySources(
            primary: replacement, primaryNumber: number, primaryPurpose: .replacementKey,
            secondary: current, secondaryNumber: number, secondaryPurpose: .currentKey
        ) { handle, newKey, oldKey in
            try withBinary(newKey) { newPointer, newCount in
                try withBinary(oldKey ?? Data()) { oldPointer, oldCount in
                    var error = df_error()
                    try checkNative(
                        df_change_aes_key(
                            handle, UInt32(number.rawValue), newPointer, newCount, UInt32(version),
                            UInt32(authenticatedKey.rawValue), oldPointer, oldCount,
                            keySet.map(Int32.init) ?? -1, piccMaster ? 1 : 0,
                            timeoutMilliseconds, &error), error)
                }
            }
        }
    }
}
