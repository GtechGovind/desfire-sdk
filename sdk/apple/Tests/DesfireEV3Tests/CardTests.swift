import Foundation
import Testing

@testable import DesfireEV3

/** Decode an explicit even-length hexadecimal test vector. */
private func hex(_ value: String) -> Data {
    var bytes: [UInt8] = []
    bytes.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
        let end = value.index(index, offsetBy: 2)
        bytes.append(UInt8(value[index..<end], radix: 16)!)
        index = end
    }
    return Data(bytes)
}

/**
 * Deterministic independently authored transport traces, without real card access.
 */
private final class ReplayReader: Reader, @unchecked Sendable {
    private let lock = NSLock()
    private var script: [(Data, Data)]
    private var calls = 0
    private var resets = 0

    /**
     * Own expected requests and responses so callback comparisons are stable.
     */
    init(_ script: [([UInt8], [UInt8])]) {
        self.script = script.map { (Data($0.0), Data($0.1)) }
    }

    /**
     * Match each frame exactly and consume it once.
     */
    func exchange(_ frame: Data, timeoutMilliseconds: UInt32) throws -> Data {
        try lock.withLock {
            calls += 1
            guard !script.isEmpty else {
                throw DesfireError(.transport, "Unexpected exchange", outcome: .unknown)
            }
            let step = script.removeFirst()
            guard frame == step.0 else {
                throw DesfireError(.transport, "Wire mismatch", outcome: .notSent)
            }
            return step.1
        }
    }

    var callCount: Int { lock.withLock { calls } }
    var resetCount: Int { lock.withLock { resets } }
    var supportsReset: Bool { true }
    func reset() throws { lock.withLock { resets += 1 } }
}

/**
 * Block one exchange until cancellation or an explicit test-controlled release.
 */
private final class BlockingReader: Reader, @unchecked Sendable {
    private let lock = NSLock()
    private let gate = DispatchSemaphore(value: 0)
    private var calls = 0
    private var cancellations = 0
    private var cancelled = false
    var supportsCancel: Bool { true }
    var callCount: Int { lock.withLock { calls } }
    var cancelCount: Int { lock.withLock { cancellations } }

    /**
     * Record request admission before waiting, bounding test failure latency to two seconds.
     */
    func exchange(_ frame: Data, timeoutMilliseconds: UInt32) throws -> Data {
        lock.withLock { calls += 1 }
        _ = gate.wait(timeout: .now() + 2)
        if lock.withLock({ cancelled }) {
            throw DesfireError(.cancelled, "Reader cancelled", outcome: .unknown)
        }
        return Data([0, 1, 0, 0])
    }

    /**
     * Wake the blocked exchange as a reader cancellation would.
     */
    func cancel() {
        lock.withLock {
            cancellations += 1
            cancelled = true
        }
        gate.signal()
    }

    /**
     * Complete the operation normally without reporting cancellation.
     */
    func release() { gate.signal() }
}

/**
 * Host wire test covers native management, selected application and parsed scalar output.
 */
@Test func nativeOperationsAndOwnership() async throws {
    let reader = ReplayReader([
        ([0x6E], [0, 0x56, 0x34, 0x12]),
        ([0x5A, 0x03, 0x02, 0x01], [0]),
        ([0x6F], [0, 2, 7]),
    ])
    let card = try Card(reader: reader, options: .init(framing: .native))
    #expect(try await card.free_memory() == 0x123456)
    try await card.select_application(aid: 0x010203)
    #expect(try await card.file_ids() == Data([2, 7]))
    try await card.reset()
    #expect(reader.resetCount == 1)
    try await card.close()
    try await card.close()
    do {
        _ = try await card.file_ids()
        Issue.record("Closed card accepted operation")
    } catch let error as DesfireError {
        #expect(error.code == .staleHandle)
        #expect(error.outcome == .notSent)
    }
    #expect(reader.callCount == 3)
}

/**
 * Wrapped native commands and true ISO APDUs pass through different native command paths.
 */
@Test func wrappedAndTrueIsoFrames() async throws {
    let wrapped = ReplayReader([([0x90, 0x6F, 0, 0, 0], [2, 7, 0x91, 0])])
    let wrappedCard = try Card(reader: wrapped, options: .init(framing: .isoWrapped))
    #expect(try await wrappedCard.file_ids() == Data([2, 7]))
    try await wrappedCard.close()

    let challenge: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
    let iso = ReplayReader([([0, 0x84, 0, 0, 8], challenge + [0x90, 0])])
    let isoCard = try Card(reader: iso, options: .init(framing: .isoWrapped))
    #expect(try await isoCard.iso_get_challenge(length: 8) == Data(challenge))
    try await isoCard.close()
}

/**
 * The separately owned raw channel preserves exact native and ISO status without typed parsing.
 */
@Test func rawNativeAndIsoStatus() async throws {
    let nativeReader = ReplayReader([([0x6F], [0x9D, 0xCA, 0xFE])])
    let native = try RawCard(reader: nativeReader, options: .init(framing: .native))
    let nativeResponse = try await native.nativeFrame(framing: .native, command: 0x6F)
    #expect(nativeResponse.status == 0x9D)
    #expect(nativeResponse.data == Data([0xCA, 0xFE]))
    try await native.close()

    let isoReader = ReplayReader([([0, 0x84, 0, 0, 8], [1, 2, 3, 0x62, 0x82])])
    let iso = try RawCard(reader: isoReader, options: .init(framing: .isoWrapped))
    let isoResponse = try await iso.isoExchange(
        .init(cla: 0, instruction: 0x84, expectedLength: 8))
    #expect(isoResponse.status == 0x6282)
    #expect(isoResponse.data == Data([1, 2, 3]))
    try await iso.close()
}

/** Provider fixture proving redaction, exactly-once resolution, and pre-I/O cancellation. */
private final class FailingKeyProvider: Aes128KeyProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var resolutions = 0
    var resolutionCount: Int { lock.withLock { resolutions } }

    /** Record one request and fail with text that must not cross the SDK boundary. */
    func resolve(_ request: KeyRequest) async throws -> Aes128Key {
        lock.withLock { resolutions += 1 }
        throw DesfireError(.crypto, "private-provider-routing-secret")
    }
}

/** A failed Swift provider executes once inside admission and performs no reader I/O. */
@Test func keyProviderFailureIsNotSent() async throws {
    let reader = ReplayReader([])
    let card = try Card(reader: reader, options: .init(framing: .native))
    let keyNumber = KeyNumber(rawValue: 1)!
    let context = try Aes128DerivationContext(
        purpose: .authentication, keyNumber: keyNumber, userContext: Data("tenant".utf8))
    let provider = FailingKeyProvider()
    let request = try KeyRequest(
        reference: Data("key-reference".utf8), context: context, profile: .standardAes)
    do {
        try await card.authenticateStandardAes(
            keyNumber: keyNumber, keySource: .provider(request: request, provider: provider))
        Issue.record("Failed key provider reached authentication")
    } catch let error as DesfireError {
        #expect(error.code == .crypto)
        #expect(error.outcome == .notSent)
        #expect(error.requiresReconciliation == false)
        #expect(!error.message.contains("private-provider-routing-secret"))
    }
    #expect(provider.resolutionCount == 1)
    #expect(reader.callCount == 0)
    try await card.close()
}

/**
 * Invalid inputs and missing authentication are rejected before entering reader I/O.
 */
@Test func preflightValidation() async throws {
    let reader = ReplayReader([])
    let card = try Card(reader: reader, options: .init(framing: .native))
    do {
        try await card.select_application(aid: 0x1000000)
        Issue.record("Accepted oversized AID")
    } catch let error as DesfireError {
        #expect(error.code == .invalidArgument)
        #expect(error.outcome == .notSent)
    }
    do {
        _ = try await card.read_data(file: 1, offset: 0, length: 1, communication: .full)
        Issue.record("Accepted protected read without authentication")
    } catch let error as DesfireError {
        #expect(error.code == .sessionInvalid || error.code == .authentication)
        #expect(error.outcome == .notSent)
    }
    #expect(reader.callCount == 0)
    try await card.close()
}

/**
 * Native card status evidence is retained without retries.
 */
@Test func cardRejection() async throws {
    let reader = ReplayReader([([0x6F], [0x9D])])
    let card = try Card(reader: reader, options: .init(framing: .native))
    do {
        _ = try await card.file_ids()
        Issue.record("Card rejection was ignored")
    } catch let error as DesfireError {
        #expect(error.code == .cardRejected)
        #expect(error.outcome == .rejected)
        #expect(error.deviceStatus == 0x9D)
    }
    #expect(reader.callCount == 1)
    try await card.close()
}

/**
 * Cancelled queued work cannot cancel an unrelated active operation.
 */
@Test func queuedCancellationIsolation() async throws {
    let reader = BlockingReader()
    let card = try Card(reader: reader, options: .init(framing: .native))
    let first = Task { try await card.free_memory() }
    while reader.callCount == 0 { try await Task.sleep(for: .milliseconds(1)) }
    let second = Task { try await card.free_memory() }
    try await Task.sleep(for: .milliseconds(15))
    second.cancel()
    reader.release()
    #expect(try await first.value == 1)
    do {
        _ = try await second.value
        Issue.record("Cancelled queued operation reached native I/O")
    } catch let error as DesfireError {
        #expect(error.code == .cancelled)
        #expect(error.outcome == .notSent)
    }
    #expect(reader.callCount == 1)
    #expect(reader.cancelCount == 0)
    try await card.close()
}

/**
 * Active task cancellation invokes the independent reader cancellation callback once.
 */
@Test func activeCancellation() async throws {
    let reader = BlockingReader()
    let card = try Card(reader: reader, options: .init(framing: .native))
    let operation = Task { try await card.free_memory() }
    while reader.callCount == 0 { try await Task.sleep(for: .milliseconds(1)) }
    operation.cancel()
    do {
        _ = try await operation.value
        Issue.record("Cancelled active operation succeeded")
    } catch let error as DesfireError {
        #expect(error.code == .cancelled)
        #expect(error.outcome == .unknown)
    }
    #expect(reader.cancelCount == 1)
    #expect(reader.callCount == 1)
    try await card.close()
}

/**
 * Closing waits for an existing exchange and rejects later submissions before I/O.
 */
@Test func closeDuringOperation() async throws {
    let reader = BlockingReader()
    let card = try Card(reader: reader, options: .init(framing: .native))
    let operation = Task { try await card.free_memory() }
    while reader.callCount == 0 { try await Task.sleep(for: .milliseconds(1)) }
    let close = Task { try await card.close() }
    try await Task.sleep(for: .milliseconds(15))
    reader.release()
    #expect(try await operation.value == 1)
    try await close.value
    #expect(reader.callCount == 1)
}

/**
 * Close drops the SDK-owned reader reference while leaving caller-owned reader lifetime intact.
 */
@Test func callbackLifetime() async throws {
    var reader: ReplayReader? = ReplayReader([])
    weak let weakReader = reader
    let card = try Card(reader: reader!, options: .init(framing: .native))
    reader = nil
    #expect(weakReader != nil)
    try await card.close()
    #expect(weakReader == nil)
}

/**
 * Generated inventory covers every fallible operation from all split C headers.
 */
@Test func generatedAbiParity() throws {
    let source = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("c-api/include")
    let headers = try FileManager.default.contentsOfDirectory(
        at: source.appendingPathComponent("desfire"),
        includingPropertiesForKeys: nil)
        .filter { $0.pathExtension == "h" }
    let header = try headers.map { try String(contentsOf: $0, encoding: .utf8) }.joined()
    let expression = try NSRegularExpression(pattern: "DF_API int32_t (df_\\w+)\\(")
    let names = expression.matches(in: header, range: NSRange(header.startIndex..., in: header))
        .compactMap { Range($0.range(at: 1), in: header).map { String(header[$0]) } }
    #expect(Set(names) == Set(desfireRawOperations.map(\.symbol)))
    #expect(desfireRawOperations.count == Set(desfireRawOperations.map(\.id)).count)
}

/** Swift offline workflows preserve the independent AES transaction known answers. */
@Test func offlineTransactionVectors() async throws {
    let backend = try Aes128Key(hex("00112233445566778899AABBCCDDEEFF"))
    defer { backend.close() }
    let uid = hex("04782E21801D80")
    let input = hex(
        "3D02000000030000000000000000000000" +
            "10203000000000000000000000000000")
    let expectedMac = hex("1E285E485BA62DE1")
    let keys = try await Offline.deriveTransactionMacKeysAes(
        transactionKey: .direct(backend), uid: uid, committedCounter: 1)
    defer { keys.macKey.close(); keys.encryptionKey.close() }
    #expect(try keys.macKey.snapshot() == hex("2DB206D20F493AC4524EADE977E976B4"))
    #expect(try keys.encryptionKey.snapshot() == hex("A0DD3EA52546EC462FE0F466FEB3A62F"))
    #expect(
        try Offline.calculateTransactionMacSessionAes(
            sessionMacKey: keys.macKey, transactionInput: input) == expectedMac)
    #expect(
        try await Offline.verifyTransactionMacAes(
            transactionKey: .direct(backend), uid: uid, committedCounter: 1,
            transactionInput: input, transactionMac: expectedMac))
    #expect(
        try Offline.decryptTransactionReaderIdAes(
            sessionEncryptionKey: keys.encryptionKey,
            encryptedReaderId: hex("4CBA5402F5723FA30DFCDF9477E623F5")) ==
            hex("00112233445566778899AABBCCDDEEFF"))
}

/**
 * A callback starts a child task to prove inherited reentry detection avoids deadlock.
 */
private final class ReentrantReader: Reader, @unchecked Sendable {
    private let lock = NSLock()
    weak var card: Card?
    private var result: ErrorCode?
    var rejection: ErrorCode? { lock.withLock { result } }

    /**
     * Child work must fail before queuing another operation on this same reader.
     */
    func exchange(_ frame: Data, timeoutMilliseconds: UInt32) throws -> Data {
        guard let card else { throw DesfireError(.internal, "Missing test card") }
        let completed = DispatchSemaphore(value: 0)
        Task {
            do {
                _ = try await card.file_ids()
            } catch let error as DesfireError {
                self.lock.withLock { self.result = error.code }
            } catch {}
            completed.signal()
        }
        guard completed.wait(timeout: .now() + 2) == .success else {
            throw DesfireError(.timeout, "Callback reentry deadlocked", outcome: .unknown)
        }
        return Data([0, 1, 0, 0])
    }
}

/**
 * Callback-created tasks cannot recursively enter or wait for their own card queue.
 */
@Test func callbackReentry() async throws {
    let reader = ReentrantReader()
    let card = try Card(reader: reader, options: .init(framing: .native))
    reader.card = card
    #expect(try await card.free_memory() == 1)
    #expect(reader.rejection == .busy)
    try await card.close()
}

/**
 * Foreign reader exceptions may contain secrets and therefore must never become diagnostics.
 */
private final class ThrowingReader: Reader, @unchecked Sendable {
    private struct SensitiveError: Error, CustomStringConvertible {
        var description: String { "sensitive-reader-payload" }
    }

    /**
     * Throw an arbitrary implementation error with unknown delivery evidence.
     */
    func exchange(_ frame: Data, timeoutMilliseconds: UInt32) throws -> Data {
        throw SensitiveError()
    }
}

/**
 * Error text is redacted and unknown delivery never becomes an implicit retry.
 */
@Test func redactedReaderFailure() async throws {
    let card = try Card(reader: ThrowingReader(), options: .init(framing: .native))
    do {
        _ = try await card.free_memory()
        Issue.record("Reader exception was ignored")
    } catch let error as DesfireError {
        #expect(error.code == .transport)
        #expect(error.outcome == .unknown)
        #expect(!error.message.contains("sensitive-reader-payload"))
    }
    try await card.close()
}
