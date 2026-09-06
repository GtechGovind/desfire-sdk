import Foundation

/** Purpose for which an exportable AES-128 key is requested. */
public enum KeyPurpose: UInt32, Sendable {
    case authentication = 0
    case currentKey = 1
    case replacementKey = 2
    case delegatedApplication = 3
    case transactionMac = 4
    case offlineOperation = 5
}

/** Authentication family that will consume a resolved key. */
public enum AuthenticationProfile: UInt32, Sendable {
    case standardAes = 0
    case ev2First = 1
    case ev2NonFirst = 2
    case isoAes = 3
}

/** Card-side namespace containing a requested key. */
public enum KeyScope: UInt32, Sendable {
    case native = 0
    case isoPicc = 1
    case isoApplication = 2
}

/**
 * Mutable closeable owner of exactly sixteen AES key bytes.
 * Swift, system libraries, and the operating system may retain copies beyond this owner's reach.
 */
public final class Aes128Key: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [UInt8]

    /** Copy exactly sixteen bytes into independently wipeable storage. */
    public init(_ bytes: Data) throws {
        guard bytes.count == 16 else {
            throw DesfireError(.invalidArgument, "AES-128 key must contain exactly sixteen bytes")
        }
        storage = Array(bytes)
    }

    /** Best-effort fallback wiping when explicit close was omitted. */
    deinit { close() }

    /** Copy a live key for one immediate native or derivation call. */
    public func snapshot() throws -> Data {
        try lock.withLock {
            guard storage.count == 16 else {
                throw DesfireError(.invalidArgument, "AES-128 key is closed")
            }
            return Data(storage)
        }
    }

    /** Overwrite this owner's bytes; repeated close calls are safe. */
    public func close() {
        lock.withLock {
            storage.indices.forEach { storage[$0] = 0 }
            storage.removeAll(keepingCapacity: false)
        }
    }
}

/** Non-secret application-defined inputs for one AES derivation. */
public struct Aes128DerivationContext: Sendable {
    public var purpose: KeyPurpose
    public var keyNumber: KeyNumber
    public var application: ApplicationId?
    public var keySet: UInt8?
    public var diversificationInput: Data
    public var userContext: Data

    /** Construct bounded context without inferring UID, byte order, or application policy. */
    public init(
        purpose: KeyPurpose, keyNumber: KeyNumber, application: ApplicationId? = nil,
        keySet: UInt8? = nil, diversificationInput: Data = Data(),
        userContext: Data = Data()
    ) throws {
        guard keySet == nil || keySet! <= 15 else {
            throw DesfireError(.invalidArgument, "Key set must be zero through fifteen")
        }
        guard diversificationInput.count + userContext.count <= 65_536 else {
            throw DesfireError(.invalidArgument, "Combined key context exceeds 65536 bytes")
        }
        self.purpose = purpose
        self.keyNumber = keyNumber
        self.application = application
        self.keySet = keySet
        self.diversificationInput = diversificationInput
        self.userContext = userContext
    }
}

/** Non-secret lookup request for one scoped exportable key. */
public struct KeyRequest: Sendable {
    public var reference: Data
    public var context: Aes128DerivationContext
    public var profile: AuthenticationProfile?
    public var scope: KeyScope

    /** Construct one bounded provider request without resolving it. */
    public init(
        reference: Data, context: Aes128DerivationContext,
        profile: AuthenticationProfile? = nil, scope: KeyScope = .native
    ) throws {
        guard !reference.isEmpty, reference.count <= 1024 else {
            throw DesfireError(.invalidArgument, "Key reference must contain 1 through 1024 bytes")
        }
        self.reference = reference
        self.context = context
        self.profile = profile
        self.scope = scope
    }
}

/** Application-defined AES-128 derivation that returns a newly owned scoped key. */
public protocol Aes128KeyDeriver: Sendable {
    /** Derive exactly one key without retaining the master key or context. */
    func derive(
        masterKey: Aes128Key, context: Aes128DerivationContext
    ) async throws -> Aes128Key
}

/** Application-defined asynchronous provider for exportable AES-128 keys. */
public protocol Aes128KeyProvider: Sendable {
    /** Resolve exactly one scoped key without performing card I/O. */
    func resolve(_ request: KeyRequest) async throws -> Aes128Key
}

/** Direct, custom-derived, and provider-resolved key workflows. */
public enum KeySource: Sendable {
    case direct(Aes128Key)
    case derived(
        masterKey: Aes128Key, context: Aes128DerivationContext,
        deriver: any Aes128KeyDeriver)
    case provider(request: KeyRequest, provider: any Aes128KeyProvider)
}

/**
 * Resolve one key exactly once and replace callback diagnostics with a stable redacted failure.
 */
func resolveKeySource(
    _ source: KeySource, keyNumber: KeyNumber, profile: AuthenticationProfile?,
    scope: KeyScope, purpose: KeyPurpose = .authentication
) async throws -> Data {
    do {
        switch source {
        case .direct(let key):
            return try key.snapshot()
        case .derived(let masterKey, let context, let deriver):
            guard context.purpose == purpose, context.keyNumber == keyNumber else {
                throw DesfireError(.invalidArgument, "Derivation context does not match operation")
            }
            let resolved = try await deriver.derive(masterKey: masterKey, context: context)
            defer { resolved.close() }
            return try resolved.snapshot()
        case .provider(let request, let provider):
            guard request.context.purpose == purpose,
                request.context.keyNumber == keyNumber,
                request.profile == profile, request.scope == scope
            else {
                throw DesfireError(.invalidArgument, "Provider request does not match operation")
            }
            let resolved = try await provider.resolve(request)
            defer { resolved.close() }
            return try resolved.snapshot()
        }
    } catch is CancellationError {
        throw DesfireError(.cancelled, "AES-128 key resolution cancelled", outcome: .notSent)
    } catch let error as DesfireError where error.code == .invalidArgument {
        throw error
    } catch {
        throw DesfireError(.crypto, "AES-128 key resolution failed", outcome: .notSent)
    }
}
