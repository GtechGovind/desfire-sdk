import Foundation

/**
 * Physical reader framing, independent of native versus true ISO command semantics.
 */
public enum Framing: UInt32, Sendable {
    case native = 0
    case isoWrapped = 1
}

/**
 * EV3 file communication settings. Protected operations require prior authentication.
 */
public enum CommunicationMode: UInt32, Sendable {
    case plain = 0
    case mac = 1
    case full = 3
}

/**
 * Per-call execution evidence; unknown outcomes must be reconciled before retry.
 */
public enum Outcome: UInt32, Sendable {
    case notSent = 0
    case rejected = 1
    case succeeded = 2
    case unknown = 3
}

/**
 * Stable C ABI error categories without language-specific reinterpretation.
 */
public enum ErrorCode: UInt32, Sendable {
    case invalidArgument = 1
    case transport = 2
    case cardRemoved = 3
    case timeout = 4
    case cancelled = 5
    case malformedResponse = 6
    case cardRejected = 7
    case authentication = 8
    case integrity = 9
    case unsupported = 10
    case staleHandle = 11
    case busy = 12
    case sessionInvalid = 13
    case counterExhausted = 14
    case bufferTooSmall = 15
    case crypto = 16
    case `internal` = 17
}

/**
 * Immutable native error with redacted diagnostics and exact card status evidence.
 */
public struct DesfireError: Error, Sendable, CustomStringConvertible {
    public let code: ErrorCode
    public let outcome: Outcome
    public let deviceStatus: UInt16
    public let message: String

    /**
     * Retain caller-selected safe text and native execution evidence without payload data.
     */
    public init(
        _ code: ErrorCode, _ message: String, outcome: Outcome = .notSent,
        deviceStatus: UInt16 = 0
    ) {
        self.code = code
        self.message = message
        self.outcome = outcome
        self.deviceStatus = deviceStatus
    }

    public var description: String { "\(code): \(message)" }

    /** True when a mutation may have reached the card and must be reconciled before retry. */
    public var requiresReconciliation: Bool { outcome == .unknown }
}

/** Range-checked three-byte native application identifier. */
public struct ApplicationId: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt32

    /** Create an identifier only when it fits the documented 24-bit wire field. */
    public init?(rawValue: UInt32) {
        guard rawValue <= 0x00FF_FFFF else { return nil }
        self.rawValue = rawValue
    }
}

/** Range-checked native file number. */
public struct FileNumber: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt8

    /** Create a file number only for the documented zero-through-thirty-one range. */
    public init?(rawValue: UInt8) {
        guard rawValue <= 31 else { return nil }
        self.rawValue = rawValue
    }
}

/** Range-checked AES key number used by native and ISO authentication. */
public struct KeyNumber: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt8

    /** Create a key selector only for the documented zero-through-thirty-one range. */
    public init?(rawValue: UInt8) {
        guard rawValue <= 31 else { return nil }
        self.rawValue = rawValue
    }
}

/** Verified public metadata returned after EV2 First or NonFirst authentication. */
public struct AuthenticationInfo: Sendable, Equatable {
    public let transactionIdentifier: Data
    public let piccCapabilities: Data
    public let pcdCapabilities: Data

    /** Retain exact fixed-width metadata after native verification succeeds. */
    public init(
        transactionIdentifier: Data, piccCapabilities: Data, pcdCapabilities: Data
    ) throws {
        guard transactionIdentifier.count == 4, piccCapabilities.count == 6,
            pcdCapabilities.count == 6
        else {
            throw DesfireError(.malformedResponse, "Invalid authentication metadata width",
                               outcome: .succeeded)
        }
        self.transactionIdentifier = transactionIdentifier
        self.piccCapabilities = piccCapabilities
        self.pcdCapabilities = pcdCapabilities
    }
}

/**
 * The host owns activation and physical I/O. Exchange/reset run on one card's worker queue;
 * cancel may run concurrently and must be safe for that use. A reader must never retry a frame.
 */
public protocol Reader: AnyObject, Sendable {
    /**
     * Exchange one frame without retries; timeoutMilliseconds is a reader-enforced deadline.
     */
    func exchange(_ frame: Data, timeoutMilliseconds: UInt32) throws -> Data
    var supportsReset: Bool { get }
    var supportsCancel: Bool { get }
    /**
     * Perform a physical reset, or throw an error preserving delivery evidence.
     */
    func reset() throws
    /**
     * Request thread-safe cancellation without waiting for the exchange callback to finish.
     */
    func cancel()
}

extension Reader {
    public var supportsReset: Bool { false }
    public var supportsCancel: Bool { false }

    /**
     * Explicitly report that a physical reset is unavailable unless the reader implements it.
     */
    public func reset() throws {
        throw DesfireError(.unsupported, "Reader reset is unavailable")
    }

    /**
     * Default cancellation is a no-op; supportsCancel remains false.
     */
    public func cancel() {}
}

/**
 * Explicit connection framing and hard reader/card frame-size limits, measured in bytes.
 */
public struct TransportOptions: Sendable {
    public var framing: Framing
    public var maxTransmit: UInt32
    public var maxReceive: UInt32
    public var maxNativeFrame: UInt32

    /**
     * Use conservative native-frame defaults; the integrating reader may declare larger limits.
     */
    public init(
        framing: Framing, maxTransmit: UInt32 = 261, maxReceive: UInt32 = 4096,
        maxNativeFrame: UInt32 = 60
    ) {
        self.framing = framing
        self.maxTransmit = maxTransmit
        self.maxReceive = maxReceive
        self.maxNativeFrame = maxNativeFrame
    }
}
