import DesfireEV3
import Foundation

/** Run one public offline derivation while explicitly closing owned key material. */
func deriveExample() async throws -> Data {
    let master = try Aes128Key(Data(repeating: 0, count: 16))
    defer { master.close() }
    let derived = try await Offline.deriveNxpAes128(
        masterKey: .direct(master), diversification: Data([0x01]))
    defer { derived.close() }
    return try derived.snapshot()
}
