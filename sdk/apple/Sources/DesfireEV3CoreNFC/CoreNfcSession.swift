import DesfireEV3
import Foundation

#if canImport(CoreNFC)
import CoreNFC

/**
 * Owns a CoreNFC reader session and one DESFire Card in deterministic close order.
 */
@available(iOS 16.0, *)
public final class CoreNfcCardSession: @unchecked Sendable {
    public let card: Card
    private let transport: CoreNfcTransport
    private let lock = NSLock()
    private var closed = false

    /**
     * Build a portable Card over one already-connected CoreNFC ISO 7816 tag.
     */
    public init(session: NFCTagReaderSession, tag: NFCISO7816Tag) throws {
        let transport = CoreNfcTransport(session: session, tag: tag)
        self.transport = transport
        card = try Card(reader: transport, options: TransportOptions(framing: .isoWrapped))
    }

    /**
     * Drain Card work, release native callbacks, then invalidate the CoreNFC session once.
     */
    public func close() async throws {
        let shouldClose = lock.withLock { () -> Bool in
            guard !closed else { return false }
            closed = true
            return true
        }
        guard shouldClose else { return }
        do {
            try await card.close()
        } catch {
            lock.withLock { closed = false }
            throw error
        }
        transport.cancel()
    }
}
#endif
