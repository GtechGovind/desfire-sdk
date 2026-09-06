import CDesfire
import Foundation

/** Application metadata authenticated by delegated-application issuer MAC generation. */
public struct DelegatedApplicationConfiguration: Sendable {
    public var applicationId: ApplicationId
    public var keySettings: UInt8
    public var numberOfKeys: UInt8
    public var slot: UInt16
    public var slotVersion: UInt8
    public var quotaLimit: UInt16
    public var isoFileIdentifiers: Bool
    public var keySettings3: UInt8?
    public var isoId: UInt16?
    public var dfName: Data
    public var keySet: DelegatedKeySetConfiguration?

    /** Construct explicit delegated fields without choosing card policy defaults. */
    public init(
        applicationId: ApplicationId, keySettings: UInt8, numberOfKeys: UInt8,
        slot: UInt16, slotVersion: UInt8, quotaLimit: UInt16,
        isoFileIdentifiers: Bool = false, keySettings3: UInt8? = nil,
        isoId: UInt16? = nil, dfName: Data = Data(),
        keySet: DelegatedKeySetConfiguration? = nil
    ) throws {
        guard dfName.count <= 16 else {
            throw DesfireError(.invalidArgument, "Delegated DF name exceeds sixteen bytes")
        }
        self.applicationId = applicationId
        self.keySettings = keySettings
        self.numberOfKeys = numberOfKeys
        self.slot = slot
        self.slotVersion = slotVersion
        self.quotaLimit = quotaLimit
        self.isoFileIdentifiers = isoFileIdentifiers
        self.keySettings3 = keySettings3
        self.isoId = isoId
        self.dfName = dfName
        self.keySet = keySet
    }
}

/** Optional EV3 key-set fields included in delegated-application creation. */
public struct DelegatedKeySetConfiguration: Sendable {
    public var activeVersion: UInt8
    public var numberOfSets: UInt8
    public var maximumKeySize: UInt8
    public var settings: UInt8

    /** Retain the four exact documented key-set bytes. */
    public init(
        activeVersion: UInt8, numberOfSets: UInt8, maximumKeySize: UInt8,
        settings: UInt8
    ) {
        self.activeVersion = activeVersion
        self.numberOfSets = numberOfSets
        self.maximumKeySize = maximumKeySize
        self.settings = settings
    }
}

/** Independently owned transaction MAC and ReaderID session keys. */
public struct TransactionMacKeys: Sendable {
    public let macKey: Aes128Key
    public let encryptionKey: Aes128Key

    /** Adopt two exact AES keys returned by verified native derivation. */
    init(macKey: Aes128Key, encryptionKey: Aes128Key) {
        self.macKey = macKey
        self.encryptionKey = encryptionKey
    }
}

/** Stateless offline AES utilities. None of these methods communicates with a card. */
public enum Offline {
    /** Resolve one scoped key through the same direct, derived, or provider workflow. */
    private static func resolve(_ source: KeySource, purpose: KeyPurpose) async throws -> Data {
        guard let keyNumber = KeyNumber(rawValue: 0) else {
            throw DesfireError(.internal, "Invalid built-in offline key selector")
        }
        return try await resolveKeySource(
            source, keyNumber: keyNumber, profile: nil, scope: .native, purpose: purpose)
    }

    /** Overwrite one temporary Swift-owned secret copy. */
    private static func wipe(_ value: inout Data) {
        _ = value.withUnsafeMutableBytes {
            bytes in bytes.initializeMemory(as: UInt8.self, repeating: 0)
        }
        value.removeAll(keepingCapacity: false)
    }

    /** Convert one C owned-buffer result and preserve native failure evidence. */
    private static func output(
        _ operation: (UnsafeMutablePointer<OpaquePointer?>, UnsafeMutablePointer<df_error>) -> Int32
    ) throws -> Data {
        var buffer: OpaquePointer?
        var error = df_error()
        defer { df_buffer_free(buffer) }
        try checkNative(operation(&buffer, &error), error)
        return try ownedBuffer(buffer)
    }

    /** Derive one AES-128 key with the built-in NXP AN10922 construction. */
    public static func deriveNxpAes128(
        masterKey: KeySource, diversification: Data
    ) async throws -> Aes128Key {
        try validateNativeIdentity()
        var key = try await resolve(masterKey, purpose: .offlineOperation)
        defer { wipe(&key) }
        var value = try withBinary(key) { keyPointer, keyCount in
            try withBinary(diversification) { inputPointer, inputCount in
                try output {
                    df_offline_derive_nxp_aes128(
                        keyPointer, keyCount, inputPointer, inputCount, $0, $1)
                }
            }
        }
        defer { wipe(&value) }
        return try Aes128Key(value)
    }

    /** Encrypt one application default key into the documented 32-byte delegated EncK. */
    public static func encryptDelegatedDefaultKeyAes(
        damEncryptionKey: KeySource, applicationDefaultKey: KeySource,
        applicationDefaultKeyVersion: UInt8
    ) async throws -> Data {
        try validateNativeIdentity()
        var dam = try await resolve(damEncryptionKey, purpose: .delegatedApplication)
        var application = try await resolve(
            applicationDefaultKey, purpose: .delegatedApplication)
        defer {
            wipe(&dam)
            wipe(&application)
        }
        return try withBinary(dam) { damPointer, damCount in
            try withBinary(application) { applicationPointer, applicationCount in
                try output {
                    df_offline_encrypt_delegated_default_key_aes(
                        damPointer, damCount, applicationPointer, applicationCount,
                        UInt32(applicationDefaultKeyVersion), $0, $1)
                }
            }
        }
    }

    /** Calculate the issuer MAC authorizing one delegated-application creation. */
    public static func calculateDelegatedApplicationMacAes(
        damMacKey: KeySource, configuration: DelegatedApplicationConfiguration,
        encryptedDefaultKey: Data
    ) async throws -> Data {
        try validateNativeIdentity()
        var key = try await resolve(damMacKey, purpose: .delegatedApplication)
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(configuration.dfName) { namePointer, nameCount in
                try withBinary(encryptedDefaultKey) { encryptedPointer, encryptedCount in
                    var native = df_delegated_application_configuration_v1()
                    native.struct_size = UInt32(MemoryLayout.size(ofValue: native))
                    native.abi_version = 1
                    native.application_id = configuration.applicationId.rawValue
                    native.key_settings = UInt32(configuration.keySettings)
                    native.number_of_keys = UInt32(configuration.numberOfKeys)
                    native.slot = UInt32(configuration.slot)
                    native.slot_version = UInt32(configuration.slotVersion)
                    native.quota_limit = UInt32(configuration.quotaLimit)
                    native.iso_file_identifiers = configuration.isoFileIdentifiers ? 1 : 0
                    native.key_settings3 = configuration.keySettings3.map(Int32.init) ?? -1
                    native.iso_id = configuration.isoId.map(Int32.init) ?? -1
                    native.df_name = namePointer
                    native.df_name_size = nameCount
                    if let keySet = configuration.keySet {
                        native.has_key_sets = 1
                        native.active_key_set_version = UInt32(keySet.activeVersion)
                        native.number_of_key_sets = UInt32(keySet.numberOfSets)
                        native.maximum_key_size = UInt32(keySet.maximumKeySize)
                        native.key_set_settings = UInt32(keySet.settings)
                    }
                    return try output {
                        df_offline_calculate_delegated_application_mac_aes(
                            keyPointer, keyCount, &native, encryptedPointer, encryptedCount,
                            $0, $1)
                    }
                }
            }
        }
    }

    /** Calculate the issuer MAC authorizing deletion of one delegated application. */
    public static func calculateDelegatedApplicationDeleteMacAes(
        damMacKey: KeySource, applicationId: ApplicationId
    ) async throws -> Data {
        try validateNativeIdentity()
        var key = try await resolve(damMacKey, purpose: .delegatedApplication)
        defer { wipe(&key) }
        return try withBinary(key) { pointer, count in
            try output {
                df_offline_calculate_delegated_application_delete_mac_aes(
                    pointer, count, applicationId.rawValue, $0, $1)
            }
        }
    }

    /** Calculate the DAM MAC for explicit existing and replacement ISO DF names. */
    public static func calculateDelegatedConfigurationMacAes(
        damMacKey: KeySource, oldDfName: Data, newDfName: Data
    ) async throws -> Data {
        try validateNativeIdentity()
        var key = try await resolve(damMacKey, purpose: .delegatedApplication)
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(oldDfName) { oldPointer, oldCount in
                try withBinary(newDfName) { newPointer, newCount in
                    try output {
                        df_offline_calculate_delegated_configuration_mac_aes(
                            keyPointer, keyCount, oldPointer, oldCount, newPointer, newCount,
                            $0, $1)
                    }
                }
            }
        }
    }

    /** Calculate the documented MIFARE Classic compatibility-license authorization MAC. */
    public static func calculateMfcLicenseMacAes(
        licenseMacKey: KeySource, license: Data, sectorSecrets: Data
    ) async throws -> Data {
        try validateNativeIdentity()
        var key = try await resolve(licenseMacKey, purpose: .offlineOperation)
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(license) { licensePointer, licenseCount in
                try withBinary(sectorSecrets) { secretPointer, secretCount in
                    try output {
                        df_offline_calculate_mfc_license_mac_aes(
                            keyPointer, keyCount, licensePointer, licenseCount,
                            secretPointer, secretCount, $0, $1)
                    }
                }
            }
        }
    }

    /** Derive independent transaction MAC and ReaderID encryption session keys. */
    public static func deriveTransactionMacKeysAes(
        transactionKey: KeySource, uid: Data, committedCounter: UInt32
    ) async throws -> TransactionMacKeys {
        try validateNativeIdentity()
        var key = try await resolve(transactionKey, purpose: .transactionMac)
        defer { wipe(&key) }
        var value = try withBinary(key) { keyPointer, keyCount in
            try withBinary(uid) { uidPointer, uidCount in
                try output {
                    df_offline_derive_transaction_mac_keys_aes(
                        keyPointer, keyCount, committedCounter, uidPointer, uidCount, $0, $1)
                }
            }
        }
        defer { wipe(&value) }
        guard value.count == 32 else {
            throw DesfireError(.internal, "Native transaction derivation returned invalid length")
        }
        return try TransactionMacKeys(
            macKey: Aes128Key(value.prefix(16)),
            encryptionKey: Aes128Key(value.suffix(16)))
    }

    /** Calculate one TMV from an already-derived transaction MAC session key. */
    public static func calculateTransactionMacSessionAes(
        sessionMacKey: Aes128Key, transactionInput: Data
    ) throws -> Data {
        try validateNativeIdentity()
        var key = try sessionMacKey.snapshot()
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(transactionInput) { inputPointer, inputCount in
                try output {
                    df_offline_calculate_transaction_mac_session_aes(
                        keyPointer, keyCount, inputPointer, inputCount, $0, $1)
                }
            }
        }
    }

    /** Calculate one TMV directly from the backend key and explicit transaction evidence. */
    public static func calculateTransactionMacAes(
        transactionKey: KeySource, uid: Data, committedCounter: UInt32,
        transactionInput: Data
    ) async throws -> Data {
        try validateNativeIdentity()
        var key = try await resolve(transactionKey, purpose: .transactionMac)
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(uid) { uidPointer, uidCount in
                try withBinary(transactionInput) { inputPointer, inputCount in
                    try output {
                        df_offline_calculate_transaction_mac_aes(
                            keyPointer, keyCount, committedCounter, uidPointer, uidCount,
                            inputPointer, inputCount, $0, $1)
                    }
                }
            }
        }
    }

    /** Verify one TMV; callers must separately enforce committed-counter replay policy. */
    public static func verifyTransactionMacAes(
        transactionKey: KeySource, uid: Data, committedCounter: UInt32,
        transactionInput: Data, transactionMac: Data
    ) async throws -> Bool {
        try validateNativeIdentity()
        var key = try await resolve(transactionKey, purpose: .transactionMac)
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(uid) { uidPointer, uidCount in
                try withBinary(transactionInput) { inputPointer, inputCount in
                    try withBinary(transactionMac) { macPointer, macCount in
                        var verified: UInt32 = 0
                        var error = df_error()
                        try checkNative(
                            df_offline_verify_transaction_mac_aes(
                                keyPointer, keyCount, committedCounter, uidPointer, uidCount,
                                inputPointer, inputCount, macPointer, macCount, &verified, &error),
                            error)
                        return verified != 0
                    }
                }
            }
        }
    }

    /** Decrypt one authenticated EncTMRI with an already-derived transaction encryption key. */
    public static func decryptTransactionReaderIdAes(
        sessionEncryptionKey: Aes128Key, encryptedReaderId: Data
    ) throws -> Data {
        try validateNativeIdentity()
        var key = try sessionEncryptionKey.snapshot()
        defer { wipe(&key) }
        return try withBinary(key) { keyPointer, keyCount in
            try withBinary(encryptedReaderId) { encryptedPointer, encryptedCount in
                try output {
                    df_offline_decrypt_transaction_reader_id_aes(
                        keyPointer, keyCount, encryptedPointer, encryptedCount, $0, $1)
                }
            }
        }
    }

    /** Verify one raw-UID secp224r1 originality signature with an explicit trust anchor. */
    public static func verifyOriginalityUidSignature(
        publicKey: Data, uid: Data, signature: Data
    ) throws -> Bool {
        try validateNativeIdentity()
        return try withBinary(publicKey) { publicKeyPointer, publicKeyCount in
            try withBinary(uid) { uidPointer, uidCount in
                try withBinary(signature) { signaturePointer, signatureCount in
                    var verified: UInt32 = 0
                    var error = df_error()
                    try checkNative(
                        df_offline_verify_originality_uid_signature(
                            "secp224r1", publicKeyPointer, publicKeyCount, uidPointer, uidCount,
                            signaturePointer, signatureCount, &verified, &error), error)
                    return verified != 0
                }
            }
        }
    }
}
