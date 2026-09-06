import CDesfire
import Foundation

/** Convert fixed C authentication metadata only after the native verifier succeeds. */
private func authenticationInfo(_ value: inout df_authentication_info_v1) throws
    -> AuthenticationInfo
{
    let transactionIdentifier = withUnsafeBytes(of: &value.transaction_identifier) { Data($0) }
    let piccCapabilities = withUnsafeBytes(of: &value.picc_capabilities) { Data($0) }
    let pcdCapabilities = withUnsafeBytes(of: &value.pcd_capabilities) { Data($0) }
    return try AuthenticationInfo(
        transactionIdentifier: transactionIdentifier,
        piccCapabilities: piccCapabilities,
        pcdCapabilities: pcdCapabilities)
}

extension Card {
    /** Establish native Standard AES from a direct, derived, or provider-resolved key. */
    public func authenticateStandardAes(
        keyNumber: KeyNumber, keySource: KeySource,
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        try await performWithKeySource(
            keySource, keyNumber: keyNumber, profile: .standardAes, scope: .native
        ) { handle, key in
            try withBinary(key) { pointer, count in
                var error = df_error()
                try checkNative(
                    df_authenticate_standard_aes(
                        handle, UInt32(keyNumber.rawValue), pointer, count,
                        timeoutMilliseconds, &error), error)
            }
        }
    }

    /** Establish EV2 First without PCD capability input and return verified public metadata. */
    public func authenticateEv2FirstAes(
        keyNumber: KeyNumber, keySource: KeySource,
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> AuthenticationInfo {
        try await performWithKeySource(
            keySource, keyNumber: keyNumber, profile: .ev2First, scope: .native
        ) { handle, key in
            try withBinary(key) { pointer, count in
                var information = df_authentication_info_v1()
                information.struct_size = UInt32(MemoryLayout<df_authentication_info_v1>.size)
                information.abi_version = 1
                var error = df_error()
                try checkNative(
                    df_authenticate_ev2_first_aes(
                        handle, UInt32(keyNumber.rawValue), pointer, count,
                        timeoutMilliseconds, &information, &error), error)
                return try authenticationInfo(&information)
            }
        }
    }

    /** Establish EV2 First with zero through six explicit PCD capability bytes. */
    public func authenticateEv2FirstAesWithCapabilities(
        keyNumber: KeyNumber, keySource: KeySource,
        pcdCapabilities: Data = Data(), timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> AuthenticationInfo {
        guard pcdCapabilities.count <= 6 else {
            throw DesfireError(
                .invalidArgument, "PCD capabilities must contain zero through six bytes")
        }
        return try await performWithKeySource(
            keySource, keyNumber: keyNumber, profile: .ev2First, scope: .native
        ) { handle, key in
            try withBinary(key) { keyPointer, keyCount in
                try withBinary(pcdCapabilities) { capabilityPointer, capabilityCount in
                    var information = df_authentication_info_v1()
                    information.struct_size = UInt32(
                        MemoryLayout<df_authentication_info_v1>.size)
                    information.abi_version = 1
                    var error = df_error()
                    try checkNative(
                        df_authenticate_ev2_first_aes_with_capabilities(
                            handle, UInt32(keyNumber.rawValue), keyPointer, keyCount,
                            capabilityPointer, capabilityCount, timeoutMilliseconds,
                            &information, &error), error)
                    return try authenticationInfo(&information)
                }
            }
        }
    }

    /** Replace an EV2 session through NonFirst while preserving its transaction state. */
    public func authenticateEv2NonFirstAes(
        keyNumber: KeyNumber, keySource: KeySource,
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> AuthenticationInfo {
        try await performWithKeySource(
            keySource, keyNumber: keyNumber, profile: .ev2NonFirst, scope: .native
        ) { handle, key in
            try withBinary(key) { pointer, count in
                var information = df_authentication_info_v1()
                information.struct_size = UInt32(MemoryLayout<df_authentication_info_v1>.size)
                information.abi_version = 1
                var error = df_error()
                try checkNative(
                    df_authenticate_ev2_non_first_aes(
                        handle, UInt32(keyNumber.rawValue), pointer, count,
                        timeoutMilliseconds, &information, &error), error)
                return try authenticationInfo(&information)
            }
        }
    }

    /** Establish ISO mutual AES in PICC-master or application-key scope. */
    public func authenticateIsoAes(
        keyNumber: KeyNumber, applicationKey: Bool, keySource: KeySource,
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        let scope: KeyScope = applicationKey ? .isoApplication : .isoPicc
        try await performWithKeySource(
            keySource, keyNumber: keyNumber, profile: .isoAes, scope: scope
        ) { handle, key in
            try withBinary(key) { pointer, count in
                var error = df_error()
                try checkNative(
                    df_authenticate_iso_aes(
                        handle, UInt32(keyNumber.rawValue), applicationKey ? 1 : 0,
                        pointer, count, timeoutMilliseconds, &error), error)
            }
        }
    }
}
