import CDesfire
import Dispatch
import Foundation

/** Exact native response data and status returned by an expert raw exchange. */
public struct RawNativeResponse: Sendable {
    public let data: Data
    public let status: UInt8
}

/** Exact ISO/IEC 7816 response data and status word returned by an expert raw exchange. */
public struct RawISOResponse: Sendable {
    public let data: Data
    public let status: UInt16
}

/** Length representation selected for one expert ISO APDU. */
public enum RawISOLengthEncoding: UInt32, Sendable {
    case automatic = 0
    case short = 1
    case extended = 2
}

/** Session family selected for one explicit secure-native exchange. */
public enum RawSecureProfile: UInt32, Sendable {
    case standardAes = 1
    case ev2 = 2
}

/**
 * Complete expert-native logical request with explicit framing and continuation policy.
 * The core treats command and data as opaque bytes and does not infer command semantics.
 */
public struct RawNativeRequest: Sendable {
    public var framing: Framing
    public var command: UInt8
    public var data: Data
    public var maximumResponse: Int
    public var firstFrameDataSize: Int?
    public var singleContinuation: Bool

    /** Construct one bounded request without transmitting it. */
    public init(
        framing: Framing, command: UInt8, data: Data = Data(),
        maximumResponse: Int = 65_536, firstFrameDataSize: Int? = nil,
        singleContinuation: Bool = false
    ) {
        self.framing = framing
        self.command = command
        self.data = data
        self.maximumResponse = maximumResponse
        self.firstFrameDataSize = firstFrameDataSize
        self.singleContinuation = singleContinuation
    }
}

/** Complete expert ISO/IEC 7816 APDU with explicit length and continuation controls. */
public struct RawISORequest: Sendable {
    public var cla: UInt8
    public var instruction: UInt8
    public var p1: UInt8
    public var p2: UInt8
    public var data: Data
    public var expectedLength: UInt32?
    public var lengthEncoding: RawISOLengthEncoding
    public var correctReadOnlyLength: Bool
    public var maximumResponse: Int
    public var maximumFrames: Int

    /** Construct one bounded APDU without transmitting it. */
    public init(
        cla: UInt8, instruction: UInt8, p1: UInt8 = 0, p2: UInt8 = 0,
        data: Data = Data(), expectedLength: UInt32? = nil,
        lengthEncoding: RawISOLengthEncoding = .automatic,
        correctReadOnlyLength: Bool = false, maximumResponse: Int = 65_536,
        maximumFrames: Int = 32
    ) {
        self.cla = cla
        self.instruction = instruction
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expectedLength = expectedLength
        self.lengthEncoding = lengthEncoding
        self.correctReadOnlyLength = correctReadOnlyLength
        self.maximumResponse = maximumResponse
        self.maximumFrames = maximumFrames
    }
}

/**
 * Explicit secure-native layout. Header and data boundaries are caller supplied because an
 * arbitrary opcode has no safe inferred secure-messaging policy.
 */
public struct RawSecureNativeRequest: Sendable {
    public var profile: RawSecureProfile
    public var command: UInt8
    public var header: Data
    public var data: Data
    public var requestCommunication: CommunicationMode
    public var responseCommunication: CommunicationMode
    public var minimumResponse: Int
    public var maximumResponse: Int
    public var firstFrameDataSize: Int?
    public var singleContinuation: Bool
    public var invalidatesSession: Bool

    /** Construct one explicit secure request without deriving any command-specific policy. */
    public init(
        profile: RawSecureProfile, command: UInt8, header: Data = Data(), data: Data = Data(),
        requestCommunication: CommunicationMode, responseCommunication: CommunicationMode,
        minimumResponse: Int = 0, maximumResponse: Int = 65_536,
        firstFrameDataSize: Int? = nil, singleContinuation: Bool = false,
        invalidatesSession: Bool = false
    ) {
        self.profile = profile
        self.command = command
        self.header = header
        self.data = data
        self.requestCommunication = requestCommunication
        self.responseCommunication = responseCommunication
        self.minimumResponse = minimumResponse
        self.maximumResponse = maximumResponse
        self.firstFrameDataSize = firstFrameDataSize
        self.singleContinuation = singleContinuation
        self.invalidatesSession = invalidatesSession
    }
}

/**
 * Separately owned expert channel for native, ISO-wrapped-native, true ISO, and explicitly
 * configured secure exchanges. It never shares a transport with a managed ``Card``.
 */
public final class RawCard: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.desfire.ev3.raw-card")
    private let stateLock = NSRecursiveLock()
    private let identifier: UUID
    private var handle: df_raw_channel
    private var readerContext: UnsafeMutableRawPointer?
    private var closing = false
    private var closed = false
    private var cancelActive = false
    private var activeToken: OperationToken?

    /** Open an independent expert channel and retain its reader until close succeeds. */
    public init(reader: any Reader, options: TransportOptions) throws {
        try validateNativeIdentity()
        identifier = UUID()
        let context = Unmanaged.passRetained(ReaderBox(reader, identifier: identifier)).toOpaque()
        var transport = df_transport_v1()
        transport.struct_size = UInt32(MemoryLayout<df_transport_v1>.size)
        transport.abi_version = 1
        transport.framing = options.framing.rawValue
        transport.max_transmit = options.maxTransmit
        transport.max_receive = options.maxReceive
        transport.max_native_frame = options.maxNativeFrame
        transport.context = context
        transport.exchange = exchangeCallback
        transport.cancel = reader.supportsCancel ? cancelCallback : nil
        transport.reset = reader.supportsReset ? resetCallback : nil
        var nativeHandle: df_raw_channel = 0
        var error = df_error()
        do {
            try checkNative(df_raw_open(&transport, &nativeHandle, &error), error)
        } catch {
            Unmanaged<ReaderBox>.fromOpaque(context).release()
            throw error
        }
        handle = nativeHandle
        readerContext = context
    }

    /** Final cleanup fallback for a caller that omitted close. */
    deinit {
        guard !closed else { return }
        var error = df_error()
        if df_raw_close(handle, &error) == 0, let readerContext {
            Unmanaged<ReaderBox>.fromOpaque(readerContext).release()
        }
    }

    /** Admit one expert operation and preserve its FIFO position through all preflight work. */
    private func performAdmitted<T: Sendable>(
        _ operation: @escaping @Sendable (df_raw_channel, OperationToken) throws -> T
    ) async throws -> T {
        try rejectCallbackReentry()
        let token = OperationToken()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                stateLock.withLock {
                    guard !closed && !closing else {
                        continuation.resume(
                            throwing: DesfireError(.staleHandle, "Raw channel is closing or closed"))
                        return
                    }
                    queue.async {
                        do {
                            let nativeHandle = try self.stateLock.withLock {
                                guard !self.closed else {
                                    throw DesfireError(.staleHandle, "Raw channel is closed")
                                }
                                guard !token.isCancelled else {
                                    throw DesfireError(.cancelled, "Queued raw operation cancelled")
                                }
                                self.activeToken = token
                                return self.handle
                            }
                            defer { self.stateLock.withLock { self.activeToken = nil } }
                            continuation.resume(returning: try operation(nativeHandle, token))
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                }
            }
        } onCancel: {
            token.cancel()
            self.cancelIfActive(token)
        }
    }

    /** Execute one expert native operation in FIFO order without retrying any frame. */
    private func perform<T: Sendable>(
        _ operation: @escaping @Sendable (df_raw_channel) throws -> T
    ) async throws -> T {
        try await performAdmitted { handle, token in
            try token.beginNative()
            return try operation(handle)
        }
    }

    /** Resolve one raw-session key inside FIFO admission before the first authentication frame. */
    private func performWithKeySource<T: Sendable>(
        _ source: KeySource, keyNumber: KeyNumber, profile: AuthenticationProfile,
        scope: KeyScope, operation: @escaping @Sendable (df_raw_channel, Data) throws -> T
    ) async throws -> T {
        try await performAdmitted { handle, token in
            var key = try waitForPreflight(token: token) {
                try await resolveKeySource(
                    source, keyNumber: keyNumber, profile: profile, scope: scope)
            }
            defer {
                _ = key.withUnsafeMutableBytes {
                    bytes in bytes.initializeMemory(as: UInt8.self, repeating: 0)
                }
                key.removeAll(keepingCapacity: false)
            }
            try token.beginNative()
            return try operation(handle, key)
        }
    }

    /** Reject reader-callback recursion before it can wait on this channel's own queue. */
    private func rejectCallbackReentry() throws {
        guard CallbackContext.cardIdentifier != identifier else {
            throw DesfireError(.busy, "Same-channel reader callback reentry is not permitted")
        }
    }

    /** Request cancellation only when the matching task has reached native execution. */
    private func cancelIfActive(_ token: OperationToken) {
        stateLock.withLock {
            guard !closed, activeToken === token, token.hasStartedNative, !cancelActive else {
                return
            }
            cancelActive = true
            defer { cancelActive = false }
            var error = df_error()
            _ = df_raw_cancel(handle, &error)
        }
    }

    /** Exchange exactly one physical native frame and preserve its status byte. */
    public func nativeFrame(
        framing: Framing, command: UInt8, data: Data = Data(),
        timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> RawNativeResponse {
        try await perform { handle in
            try withBinary(data) { pointer, count in
                var status: UInt32 = 0
                var output: OpaquePointer?
                var error = df_error()
                defer { df_buffer_free(output) }
                try checkNative(
                    df_raw_native_frame(
                        handle, framing.rawValue, UInt32(command), pointer, count,
                        timeoutMilliseconds, &status, &output, &error), error)
                guard status <= UInt8.max else {
                    throw DesfireError(.internal, "Native status exceeds one byte", outcome: .succeeded)
                }
                return RawNativeResponse(data: try ownedBuffer(output), status: UInt8(status))
            }
        }
    }

    /** Exchange one bounded native logical command with the requested AF policy. */
    public func nativeExchange(
        _ value: RawNativeRequest, timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> RawNativeResponse {
        try await perform { handle in
            try withBinary(value.data) { pointer, count in
                var request = df_native_request_v1()
                request.struct_size = UInt32(MemoryLayout<df_native_request_v1>.size)
                request.abi_version = 1
                request.framing = value.framing.rawValue
                request.command = UInt32(value.command)
                request.data = pointer
                request.data_size = count
                request.maximum_response = value.maximumResponse
                request.first_frame_data_size = value.firstFrameDataSize ?? -1
                request.flags = value.singleContinuation ? 1 : 0
                var status: UInt32 = 0
                var output: OpaquePointer?
                var error = df_error()
                defer { df_buffer_free(output) }
                try checkNative(
                    df_raw_native_exchange(
                        handle, &request, timeoutMilliseconds, &status, &output, &error), error)
                guard status <= UInt8.max else {
                    throw DesfireError(.internal, "Native status exceeds one byte", outcome: .succeeded)
                }
                return RawNativeResponse(data: try ownedBuffer(output), status: UInt8(status))
            }
        }
    }

    /** Exchange one true ISO APDU and preserve warning or error status with returned data. */
    public func isoExchange(
        _ value: RawISORequest, timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> RawISOResponse {
        try await perform { handle in
            try withBinary(value.data) { pointer, count in
                var request = df_iso_apdu_v1()
                request.struct_size = UInt32(MemoryLayout<df_iso_apdu_v1>.size)
                request.abi_version = 1
                request.cla = UInt32(value.cla)
                request.ins = UInt32(value.instruction)
                request.p1 = UInt32(value.p1)
                request.p2 = UInt32(value.p2)
                request.data = pointer
                request.data_size = count
                request.has_le = value.expectedLength == nil ? 0 : 1
                request.le = value.expectedLength ?? 0
                request.length_encoding = value.lengthEncoding.rawValue
                request.correct_length = value.correctReadOnlyLength ? 1 : 0
                request.maximum_response = value.maximumResponse
                request.maximum_frames = value.maximumFrames
                var status: UInt32 = 0
                var output: OpaquePointer?
                var error = df_error()
                defer { df_buffer_free(output) }
                try checkNative(
                    df_raw_iso_exchange(
                        handle, &request, timeoutMilliseconds, &status, &output, &error), error)
                guard status <= UInt16.max else {
                    throw DesfireError(.internal, "ISO status exceeds two bytes", outcome: .succeeded)
                }
                return RawISOResponse(data: try ownedBuffer(output), status: UInt16(status))
            }
        }
    }

    /**
     * Exchange a checked ISO data/EF command through the active raw ISO AES session.
     * Unsupported APDUs and DF selection fail before transport I/O.
     */
    public func isoSecureExchange(
        _ value: RawISORequest, timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> RawISOResponse {
        try await perform { handle in
            try withBinary(value.data) { pointer, count in
                var request = df_iso_apdu_v1()
                request.struct_size = UInt32(MemoryLayout<df_iso_apdu_v1>.size)
                request.abi_version = 1
                request.cla = UInt32(value.cla)
                request.ins = UInt32(value.instruction)
                request.p1 = UInt32(value.p1)
                request.p2 = UInt32(value.p2)
                request.data = pointer
                request.data_size = count
                request.has_le = value.expectedLength == nil ? 0 : 1
                request.le = value.expectedLength ?? 0
                request.length_encoding = value.lengthEncoding.rawValue
                request.correct_length = value.correctReadOnlyLength ? 1 : 0
                request.maximum_response = value.maximumResponse
                request.maximum_frames = value.maximumFrames
                var status: UInt32 = 0
                var output: OpaquePointer?
                var error = df_error()
                defer { df_buffer_free(output) }
                try checkNative(
                    df_raw_iso_secure_exchange(
                        handle, &request, timeoutMilliseconds, &status, &output, &error), error)
                guard status <= UInt16.max else {
                    throw DesfireError(.internal, "ISO status exceeds two bytes", outcome: .succeeded)
                }
                return RawISOResponse(data: try ownedBuffer(output), status: UInt16(status))
            }
        }
    }

    /** Install Standard AES using one caller-supplied exact key. */
    public func authenticateStandardAes(
        keyNumber: UInt8, key: Data, timeoutMilliseconds: UInt32 = 5_000
    ) async throws {
        try await perform { handle in
            try withBinary(key) { pointer, count in
                var error = df_error()
                try checkNative(
                    df_raw_authenticate_standard_aes(
                        handle, UInt32(keyNumber), pointer, count, timeoutMilliseconds, &error),
                    error)
            }
        }
    }

    /** Install Standard AES after direct, derived, or provider key resolution inside admission. */
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
                    df_raw_authenticate_standard_aes(
                        handle, UInt32(keyNumber.rawValue), pointer, count,
                        timeoutMilliseconds, &error), error)
            }
        }
    }

    /** Install EV2 First with explicit capabilities and return verified public metadata. */
    public func authenticateEv2FirstAes(
        keyNumber: KeyNumber, keySource: KeySource, pcdCapabilities: Data = Data(),
        timeoutMilliseconds: UInt32 = 5_000
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
                        df_raw_authenticate_ev2_first_aes(
                            handle, UInt32(keyNumber.rawValue), keyPointer, keyCount,
                            capabilityPointer, capabilityCount, timeoutMilliseconds,
                            &information, &error), error)
                    return try AuthenticationInfo(
                        transactionIdentifier: withUnsafeBytes(
                            of: &information.transaction_identifier) { Data($0) },
                        piccCapabilities: withUnsafeBytes(
                            of: &information.picc_capabilities) { Data($0) },
                        pcdCapabilities: withUnsafeBytes(
                            of: &information.pcd_capabilities) { Data($0) })
                }
            }
        }
    }

    /** Replace an active raw EV2 session through NonFirst and preserve TI/counter state. */
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
                    df_raw_authenticate_ev2_non_first_aes(
                        handle, UInt32(keyNumber.rawValue), pointer, count,
                        timeoutMilliseconds, &information, &error), error)
                return try AuthenticationInfo(
                    transactionIdentifier: withUnsafeBytes(
                        of: &information.transaction_identifier) { Data($0) },
                    piccCapabilities: withUnsafeBytes(
                        of: &information.picc_capabilities) { Data($0) },
                    pcdCapabilities: withUnsafeBytes(
                        of: &information.pcd_capabilities) { Data($0) })
            }
        }
    }

    /** Establish raw ISO mutual AES in PICC-master or application-key scope. */
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
                    df_raw_authenticate_iso_aes(
                        handle, UInt32(keyNumber.rawValue), applicationKey ? 1 : 0,
                        pointer, count, timeoutMilliseconds, &error), error)
            }
        }
    }

    /** Execute a secure request using the explicitly selected installed raw session. */
    public func secureNativeExchange(
        _ value: RawSecureNativeRequest, timeoutMilliseconds: UInt32 = 5_000
    ) async throws -> Data {
        try await perform { handle in
            try withBinary(value.header) { headerPointer, headerCount in
                try withBinary(value.data) { dataPointer, dataCount in
                    var request = df_native_secure_request_v1()
                    request.struct_size = UInt32(MemoryLayout<df_native_secure_request_v1>.size)
                    request.abi_version = 1
                    request.profile = value.profile.rawValue
                    request.command = UInt32(value.command)
                    request.header = headerPointer
                    request.header_size = headerCount
                    request.data = dataPointer
                    request.data_size = dataCount
                    request.request_communication = value.requestCommunication.rawValue
                    request.response_communication = value.responseCommunication.rawValue
                    request.minimum_response = value.minimumResponse
                    request.maximum_response = value.maximumResponse
                    request.first_frame_data_size = value.firstFrameDataSize ?? -1
                    request.flags = value.singleContinuation ? 1 : 0
                    request.invalidates_session = value.invalidatesSession ? 1 : 0
                    var output: OpaquePointer?
                    var error = df_error()
                    defer { df_buffer_free(output) }
                    try checkNative(
                        df_raw_native_secure_exchange(
                            handle, &request, timeoutMilliseconds, &output, &error), error)
                    return try ownedBuffer(output)
                }
            }
        }
    }

    /** Reset the raw transport and clear every local secure session. */
    public func reset() async throws {
        try await perform { handle in
            var error = df_error()
            try checkNative(df_raw_reset(handle, &error), error)
        }
    }

    /** Invalidate raw session state after external reader or card activity. */
    public func notifyStateChange() async throws {
        try await perform { handle in
            var error = df_error()
            try checkNative(df_raw_notify_state_change(handle, &error), error)
        }
    }

    /** Request cancellation concurrently with the active raw exchange. */
    public func cancel() throws {
        try rejectCallbackReentry()
        try stateLock.withLock {
            guard !closed else { throw DesfireError(.staleHandle, "Raw channel is closed") }
            guard !cancelActive else {
                throw DesfireError(.busy, "Raw cancellation is already active")
            }
            cancelActive = true
            defer { cancelActive = false }
            var error = df_error()
            try checkNative(df_raw_cancel(handle, &error), error)
        }
    }

    /** Drain admitted work, close once, and release reader ownership after native close succeeds. */
    public func close() async throws {
        try rejectCallbackReentry()
        let alreadyClosed = stateLock.withLock {
            if closed { return true }
            closing = true
            return false
        }
        if alreadyClosed { return }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                do {
                    try self.stateLock.withLock {
                        guard !self.closed else { return }
                        var error = df_error()
                        do {
                            try checkNative(df_raw_close(self.handle, &error), error)
                        } catch {
                            self.closing = false
                            throw error
                        }
                        self.closed = true
                        if let context = self.readerContext {
                            self.readerContext = nil
                            Unmanaged<ReaderBox>.fromOpaque(context).release()
                        }
                    }
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
