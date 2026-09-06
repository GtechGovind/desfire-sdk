import CDesfire
import Dispatch
import Foundation

/**
 * Inherited by tasks created from a reader callback, preventing same-card callback deadlocks.
 */
enum CallbackContext {
    @TaskLocal static var cardIdentifier: UUID?
}

/**
 * Retained callback context; the native handle never outlives this reader reference.
 */
final class ReaderBox: @unchecked Sendable {
    let reader: any Reader
    let identifier: UUID

    /**
     * Retain the caller-owned physical reader and identify its logical card connection.
     */
    init(_ reader: any Reader, identifier: UUID) {
        self.reader = reader
        self.identifier = identifier
    }
}

/**
 * Cancellation belongs to one queued operation, never to an earlier operation on the card.
 */
final class OperationToken: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var nativeStarted = false
    private var preflightCancellation: (@Sendable () -> Void)?

    /**
     * Mark this operation cancelled even when its worker has not started.
     */
    func cancel() {
        let cancellation = lock.withLock {
            cancelled = true
            return preflightCancellation
        }
        cancellation?()
    }

    /**
     * Read cancellation without racing the task cancellation handler.
     */
    var isCancelled: Bool { lock.withLock { cancelled } }

    /** Mark the transition from preflight to native execution, or reject prior cancellation. */
    func beginNative() throws {
        try lock.withLock {
            guard !cancelled else {
                throw DesfireError(.cancelled, "Queued operation cancelled", outcome: .notSent)
            }
            preflightCancellation = nil
            nativeStarted = true
        }
    }

    /** Report whether cancellation may need to interrupt a native reader callback. */
    var hasStartedNative: Bool { lock.withLock { nativeStarted } }

    /** Install cancellation for asynchronous preflight and invoke it if already cancelled. */
    func registerPreflightCancellation(_ cancellation: @escaping @Sendable () -> Void) {
        let invoke = lock.withLock {
            preflightCancellation = cancellation
            return cancelled
        }
        if invoke { cancellation() }
    }

    /** Remove the preflight callback after its asynchronous work finishes. */
    func clearPreflightCancellation() { lock.withLock { preflightCancellation = nil } }
}

/** Thread-safe result rendezvous used only by one card's blocking native worker. */
private final class AsyncPreflightResult<Value: Sendable>: @unchecked Sendable {
    private let condition = NSCondition()
    private var result: Result<Value, Error>?

    /** Publish one result and wake the card worker. */
    func complete(_ value: Result<Value, Error>) {
        condition.lock()
        result = value
        condition.broadcast()
        condition.unlock()
    }

    /** Wait on the private card worker and return the published result. */
    func wait() throws -> Value {
        condition.lock()
        while result == nil { condition.wait() }
        let completed = result!
        condition.unlock()
        return try completed.get()
    }
}

/**
 * Run asynchronous key work while preserving the card worker's FIFO admission position.
 */
func waitForPreflight<Value: Sendable>(
    token: OperationToken, operation: @escaping @Sendable () async throws -> Value
) throws -> Value {
    let result = AsyncPreflightResult<Value>()
    let task = Task {
        do {
            result.complete(.success(try await operation()))
        } catch {
            result.complete(.failure(error))
        }
    }
    token.registerPreflightCancellation { task.cancel() }
    defer { token.clearPreflightCancellation() }
    return try result.wait()
}

/**
 * Write bounded, redacted error evidence into a C callback result.
 */
func callbackFailure(_ error: Error, into target: UnsafeMutablePointer<df_error>?) -> Int32
{
    let native = error as? DesfireError
    let code = native?.code ?? .transport
    if let target {
        target.pointee = df_error()
        target.pointee.code = code.rawValue
        target.pointee.outcome = (native?.outcome ?? .unknown).rawValue
        target.pointee.device_status = native?.deviceStatus ?? 0
        withUnsafeMutableBytes(of: &target.pointee.message) { bytes in
            let message = Array("Reader callback failed".utf8)
            bytes.copyBytes(from: message.prefix(bytes.count - 1))
        }
    }
    return Int32(code.rawValue)
}

/**
 * The C ABI invokes this synchronously on the card queue and borrows all pointers.
 */
let exchangeCallback: df_exchange_fn = {
    context, transmit, transmitSize, receive, capacity, received, timeout, nativeError in
    guard let context, let received, transmitSize == 0 || transmit != nil,
        capacity == 0 || receive != nil
    else {
        return callbackFailure(
            DesfireError(.invalidArgument, "Invalid callback buffer"), into: nativeError)
    }
    received.pointee = 0
    let box = Unmanaged<ReaderBox>.fromOpaque(context).takeUnretainedValue()
    do {
        let frame = transmitSize == 0 ? Data() : Data(bytes: transmit!, count: transmitSize)
        let response = try CallbackContext.$cardIdentifier.withValue(box.identifier) {
            try box.reader.exchange(frame, timeoutMilliseconds: timeout)
        }
        guard response.count <= capacity else {
            throw DesfireError(
                .bufferTooSmall, "Reader response exceeds capacity", outcome: .unknown)
        }
        if let receive, !response.isEmpty {
            response.copyBytes(to: receive, count: response.count)
        }
        received.pointee = response.count
        return 0
    } catch {
        return callbackFailure(error, into: nativeError)
    }
}

/**
 * Cancellation may run concurrently with exchange; the Reader contract requires thread safety.
 */
let cancelCallback: df_cancel_fn = { context in
    guard let context else { return }
    let box = Unmanaged<ReaderBox>.fromOpaque(context).takeUnretainedValue()
    CallbackContext.$cardIdentifier.withValue(box.identifier) { box.reader.cancel() }
}

/**
 * A reset is explicit physical reader work, and callback exceptions never cross the C ABI.
 */
let resetCallback: df_reset_fn = { context, nativeError in
    guard let context else {
        return callbackFailure(
            DesfireError(.invalidArgument, "Invalid callback context"),
            into: nativeError)
    }
    let box = Unmanaged<ReaderBox>.fromOpaque(context).takeUnretainedValue()
    do {
        try CallbackContext.$cardIdentifier.withValue(box.identifier) { try box.reader.reset() }
        return 0
    } catch {
        return callbackFailure(error, into: nativeError)
    }
}

/**
 * Translate one C result without retries or changes to execution evidence.
 */
func checkNative(_ status: Int32, _ nativeError: df_error) throws {
    guard status != 0 else { return }
    var nativeError = nativeError
    let message = withUnsafeBytes(of: &nativeError.message) { bytes in
        String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
    }
    throw DesfireError(
        ErrorCode(rawValue: nativeError.code) ?? .internal,
        message.isEmpty ? "Native operation failed" : message,
        outcome: Outcome(rawValue: nativeError.outcome) ?? .unknown,
        deviceStatus: nativeError.device_status)
}

/**
 * Borrow contiguous bytes for exactly one native invocation; no pointers escape this closure.
 */
func withBinary<T>(
    _ data: Data,
    _ body: (UnsafePointer<UInt8>?, Int) throws -> T
) throws -> T {
    guard data.count <= 16 * 1024 * 1024 else {
        throw DesfireError(.invalidArgument, "Binary input exceeds SDK limit")
    }
    return try data.withUnsafeBytes { bytes in
        try body(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
}

/**
 * Copy a native result before the generated wrapper frees its owning C buffer.
 */
func ownedBuffer(_ buffer: OpaquePointer?) throws -> Data {
    guard let buffer else {
        throw DesfireError(.internal, "Native operation omitted its output", outcome: .succeeded)
    }
    let count = df_buffer_size(buffer)
    guard count <= 16 * 1024 * 1024 else {
        throw DesfireError(.internal, "Native output exceeds SDK limit", outcome: .succeeded)
    }
    guard count != 0 else { return Data() }
    guard let pointer = df_buffer_data(buffer) else {
        throw DesfireError(.internal, "Native output has no data", outcome: .succeeded)
    }
    return Data(bytes: pointer, count: count)
}

/** Require both the ABI version and canonical operation-manifest identity before opening. */
func validateNativeIdentity() throws {
    guard df_abi_version() == desfireAbiVersion else {
        throw DesfireError(.unsupported, "Incompatible native C ABI version")
    }
    guard let digest = df_manifest_sha256(),
        String(cString: digest) == desfireManifestSha256
    else {
        throw DesfireError(.unsupported, "Incompatible native API manifest")
    }
}

/**
 * One logical card connection. All protocol, cryptography and validation remain in the C ABI.
 * Native I/O is serialized on a private dispatch queue; async callers never block the UI thread.
 */
public final class Card: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.desfire.ev3.card")
    private let stateLock = NSRecursiveLock()
    private let identifier: UUID
    private var handle: df_card
    private var readerContext: UnsafeMutableRawPointer?
    private var closing = false
    private var closed = false
    private var cancelActive = false
    private var activeToken: OperationToken?

    /**
     * Open a logical native connection without selecting or mutating the physical card.
     * The SDK retains the Reader until close completes; the caller owns physical-reader shutdown.
     */
    public init(reader: any Reader, options: TransportOptions) throws {
        try validateNativeIdentity()
        identifier = UUID()
        let context = Unmanaged.passRetained(ReaderBox(reader, identifier: identifier)).toOpaque()
        var transport = df_transport()
        transport.struct_size = UInt32(MemoryLayout<df_transport>.size)
        transport.abi_version = 1
        transport.framing = options.framing.rawValue
        transport.max_transmit = options.maxTransmit
        transport.max_receive = options.maxReceive
        transport.max_native_frame = options.maxNativeFrame
        transport.context = context
        transport.exchange = exchangeCallback
        transport.cancel = reader.supportsCancel ? cancelCallback : nil
        transport.reset = reader.supportsReset ? resetCallback : nil
        var nativeHandle: df_card = 0
        var error = df_error()
        do {
            try checkNative(df_open(&transport, &nativeHandle, &error), error)
        } catch {
            Unmanaged<ReaderBox>.fromOpaque(context).release()
            throw error
        }
        handle = nativeHandle
        readerContext = context
    }

    /**
     * Final fallback for omitted close. Pending operations retain self until their native call ends.
     */
    deinit {
        guard !closed else { return }
        var error = df_error()
        if df_close(handle, &error) == 0, let readerContext {
            Unmanaged<ReaderBox>.fromOpaque(readerContext).release()
        }
    }

    /** Admit one operation and retain its FIFO position across preflight and native execution. */
    private func performAdmitted<T: Sendable>(
        _ operation: @escaping @Sendable (df_card, OperationToken) throws -> T
    ) async throws -> T {
        try rejectCallbackReentry()
        let token = OperationToken()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                stateLock.withLock {
                    guard !closed && !closing else {
                        continuation.resume(
                            throwing: DesfireError(.staleHandle, "Card is closing or closed"))
                        return
                    }
                    queue.async {
                        do {
                            let nativeHandle = try self.stateLock.withLock {
                                guard !self.closed else {
                                    throw DesfireError(.staleHandle, "Card is closing or closed")
                                }
                                guard !token.isCancelled else {
                                    throw DesfireError(.cancelled, "Queued operation cancelled")
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

    /**
     * Execute one ABI call in order, mapping task cancellation to only that operation.
     */
    func perform<T: Sendable>(_ operation: @escaping @Sendable (df_card) throws -> T) async throws
        -> T
    {
        try await performAdmitted { handle, token in
            try token.beginNative()
            return try operation(handle)
        }
    }

    /** Resolve exactly one key inside FIFO admission and invoke the direct-key C operation. */
    func performWithKeySource<T: Sendable>(
        _ source: KeySource, keyNumber: KeyNumber, profile: AuthenticationProfile?,
        scope: KeyScope, purpose: KeyPurpose = .authentication,
        operation: @escaping @Sendable (df_card, Data) throws -> T
    ) async throws -> T {
        try await performAdmitted { handle, token in
            var key = try waitForPreflight(token: token) {
                try await resolveKeySource(
                    source, keyNumber: keyNumber, profile: profile, scope: scope,
                    purpose: purpose)
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

    /** Resolve two optional secret inputs under one FIFO admission before the first card frame. */
    func performWithKeySources<T: Sendable>(
        primary: KeySource, primaryNumber: KeyNumber, primaryPurpose: KeyPurpose,
        secondary: KeySource?, secondaryNumber: KeyNumber, secondaryPurpose: KeyPurpose,
        operation: @escaping @Sendable (df_card, Data, Data?) throws -> T
    ) async throws -> T {
        try await performAdmitted { handle, token in
            var first = try waitForPreflight(token: token) {
                try await resolveKeySource(
                    primary, keyNumber: primaryNumber, profile: nil, scope: .native,
                    purpose: primaryPurpose)
            }
            var second: Data?
            defer {
                _ = first.withUnsafeMutableBytes {
                    bytes in bytes.initializeMemory(as: UInt8.self, repeating: 0)
                }
                first.removeAll(keepingCapacity: false)
                if var owned = second {
                    _ = owned.withUnsafeMutableBytes {
                        bytes in bytes.initializeMemory(as: UInt8.self, repeating: 0)
                    }
                    owned.removeAll(keepingCapacity: false)
                    second = nil
                }
            }
            if let secondary {
                second = try waitForPreflight(token: token) {
                    try await resolveKeySource(
                        secondary, keyNumber: secondaryNumber, profile: nil, scope: .native,
                        purpose: secondaryPurpose)
                }
            }
            try token.beginNative()
            return try operation(handle, first, second)
        }
    }

    /**
     * Reject callback-created calls before they can wait on their own card queue.
     */
    private func rejectCallbackReentry() throws {
        guard CallbackContext.cardIdentifier != identifier else {
            throw DesfireError(.busy, "Same-card reader callback reentry is not permitted")
        }
    }

    /**
     * Request reader cancellation concurrently; delivery evidence comes from the active operation.
     */
    public func cancel() throws {
        try rejectCallbackReentry()
        try stateLock.withLock {
            guard !closed else { throw DesfireError(.staleHandle, "Card is closed") }
            guard !cancelActive else { throw DesfireError(.busy, "Cancellation is already active") }
            cancelActive = true
            defer { cancelActive = false }
            var error = df_error()
            try checkNative(df_cancel(handle, &error), error)
        }
    }

    /**
     * Cancel only the operation represented by this task token, preserving queued-call isolation.
     */
    private func cancelIfActive(_ token: OperationToken) {
        stateLock.withLock {
            guard !closed, activeToken === token, token.hasStartedNative, !cancelActive else { return }
            cancelActive = true
            defer { cancelActive = false }
            var error = df_error()
            _ = df_cancel(handle, &error)
        }
    }

    /**
     * Explicitly reset the reader and invalidate native authentication and selection state.
     */
    public func reset() async throws {
        try await perform { handle in
            var error = df_error()
            try checkNative(df_reset(handle, &error), error)
        }
    }

    /**
     * Invalidate native state after external reader or card activity, without physical I/O.
     */
    public func notify_state_change() async throws {
        try await perform { handle in
            var error = df_error()
            try checkNative(df_notify_state_change(handle, &error), error)
        }
    }

    /**
     * Close after previously queued work completes and release the callback context exactly once.
     * Close does not cancel in-flight I/O or close the physical reader; call cancel when required.
     */
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
                            try checkNative(df_close(self.handle, &error), error)
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
