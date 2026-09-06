import DesfireEV3
import Foundation

#if canImport(CoreNFC)
    import CoreNFC

    /** Thread-safe one-shot storage shared with CoreNFC's concurrent completion callback. */
    private final class CoreNfcExchangeResult: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Data, Error>?

        /** Publish the single terminal exchange result. */
        func complete(_ value: Result<Data, Error>) {
            lock.withLock { result = value }
        }

        /** Read the terminal result after the completion semaphore has been signalled. */
        func read() -> Result<Data, Error>? {
            lock.withLock { result }
        }
    }

    /**
     * A connected ISO 14443 tag transport. It owns no discovery policy and never reconnects.
     *
     * Construct this object only after CoreNFC has connected the supplied tag. A failure or
     * cancellation invalidates the owning reader session; the application must explicitly discover
     * a new tag and build a new Card before further exchanges.
     */
    @available(iOS 16.0, *)
    public final class CoreNfcTransport: Reader, @unchecked Sendable {
        private let lock = NSLock()
        private var session: NFCTagReaderSession?
        private var tag: NFCISO7816Tag?
        private var cancelled = false

        /**
         * Retain one already-connected tag and its owning session for explicit invalidation.
         */
        public init(session: NFCTagReaderSession, tag: NFCISO7816Tag) {
            self.session = session
            self.tag = tag
        }

        public var supportsReset: Bool { false }
        public var supportsCancel: Bool { true }

        /**
         * Send one complete APDU through the connected tag and append SW1/SW2 to response data.
         */
        public func exchange(_ frame: Data, timeoutMilliseconds: UInt32) throws -> Data {
            guard timeoutMilliseconds > 0 else {
                throw DesfireError(.invalidArgument, "CoreNFC timeout must be positive")
            }
            guard let command = NFCISO7816APDU(data: frame) else {
                throw DesfireError(.invalidArgument, "CoreNFC requires one complete ISO APDU")
            }
            let activeTag = try lock.withLock { () throws -> NFCISO7816Tag in
                guard !cancelled, let tag else {
                    throw DesfireError(.cardRemoved, "CoreNFC tag session is unavailable")
                }
                return tag
            }

            let completed = DispatchSemaphore(value: 0)
            let exchangeResult = CoreNfcExchangeResult()
            activeTag.sendCommand(apdu: command) { data, sw1, sw2, error in
                if let error {
                    exchangeResult.complete(.failure(error))
                } else {
                    var response = data
                    response.append(sw1)
                    response.append(sw2)
                    exchangeResult.complete(.success(response))
                }
                completed.signal()
            }

            let deadline = DispatchTime.now() + .milliseconds(Int(timeoutMilliseconds))
            guard completed.wait(timeout: deadline) == .success else {
                cancel()
                throw DesfireError(.timeout, "CoreNFC exchange timed out", outcome: .unknown)
            }
            switch exchangeResult.read() {
            case .success(let response):
                return response
            case .failure:
                lock.withLock { tag = nil }
                throw DesfireError(.transport, "CoreNFC exchange failed", outcome: .unknown)
            case nil:
                throw DesfireError(
                    .internal, "CoreNFC completion omitted its result",
                    outcome: .unknown)
            }
        }

        /**
         * Report that CoreNFC cannot reset a connected tag without explicit rediscovery.
         */
        public func reset() throws {
            throw DesfireError(.unsupported, "CoreNFC does not expose an in-place tag reset")
        }

        /**
         * Invalidate the owning CoreNFC session and make this transport permanently unusable.
         */
        public func cancel() {
            let activeSession = lock.withLock { () -> NFCTagReaderSession? in
                cancelled = true
                tag = nil
                let value = session
                session = nil
                return value
            }
            activeSession?.invalidate()
        }
    }
#endif
