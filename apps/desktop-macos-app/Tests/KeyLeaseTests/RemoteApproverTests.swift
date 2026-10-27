import CryptoKit
import XCTest
@testable import KeyLease

import KeyLeaseCore

/// Pins the approver wire format to the node's (`approver_signing_input` in
/// `crates/keylease-service/src/remote.rs`, which asserts the same bytes).
final class RemoteApproverTests: XCTestCase {
    func testSigningInputMatchesTheNode() {
        let input = RemoteApproverClient.signingInput(
            method: "POST", path: "/v1/approvals/a/decide",
            timestamp: 1_700_000_000, body: Data(#"{"approve":true}"#.utf8))
        XCTAssertEqual(
            String(decoding: input, as: UTF8.self),
            "KEYLEASE-APPROVER-V1\nPOST\n/v1/approvals/a/decide\n1700000000\n"
                + "d80736cb968002b333b9dbd349375db423a42c381558798f8abba960c41a5862")
    }

    /// The key files hold the 32-byte Ed25519 seed (RFC 8032 test 1), the
    /// same representation `ed25519_dalek::SigningKey::from_bytes` takes.
    func testSeedRepresentationMatchesEd25519Dalek() throws {
        let seed = Data(hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        XCTAssertEqual(
            key.publicKey.rawRepresentation,
            Data(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        let message = Data("m".utf8)
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                try key.signature(for: message), for: message))
    }

    func testOnlyHttpsOrLoopbackNodes() {
        XCTAssertNoThrow(try RemoteApproverStore.validatedURL("https://vault.example.com"))
        XCTAssertNoThrow(try RemoteApproverStore.validatedURL("http://127.0.0.1:7443"))
        XCTAssertThrowsError(try RemoteApproverStore.validatedURL("http://vault.example.com"))
        XCTAssertThrowsError(try RemoteApproverStore.validatedURL("ftp://vault.example.com"))
        XCTAssertFalse(RemoteApproverStore.isValidName("../etc"))
        XCTAssertTrue(RemoteApproverStore.isValidName("vps-1"))
    }
}

private extension Data {
    init(hex: String) {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
