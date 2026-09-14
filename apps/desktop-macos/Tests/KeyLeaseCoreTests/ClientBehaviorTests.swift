import Foundation
import XCTest

@testable import KeyLeaseCore

/// Client-side guarantees that do not need a recorded vector: token file
/// validation, size bounds, transport failure and malformed envelopes.
final class ClientBehaviorTests: XCTestCase {
    private func client(
        socketPath: String, tokenPath: String
    ) -> KeyLeaseRpc {
        KeyLeaseRpc(
            socketPath: socketPath, agentId: "agent_test",
            tokenPath: tokenPath, sessionId: "test"
        )
    }

    // MARK: token file validation (mirrors the Dart auth() checks)

    func testRejectsMissingTokenFile() async {
        let rpc = client(
            socketPath: "/nonexistent.sock",
            tokenPath: "/nonexistent-token"
        )
        await assertThrowsCode(.client) {
            _ = try await rpc.authorized(.status)
        }
    }

    func testRejectsSymlinkTokenFile() async throws {
        let target = try writeTokenFile()
        let link = NSTemporaryDirectory()
            .appendingPathComponent("keylease-test-\(UUID().uuidString)")
        try FileManager.default.createSymbolicLink(
            atPath: link, withDestinationPath: target
        )
        defer {
            try? FileManager.default.removeItem(atPath: link)
            try? FileManager.default.removeItem(atPath: target)
        }
        let rpc = client(socketPath: "/nonexistent.sock", tokenPath: link)
        await assertThrowsCode(.client) {
            _ = try await rpc.authorized(.status)
        }
    }

    func testRejectsGroupReadableTokenFile() async throws {
        let path = try writeTokenFile(mode: 0o640)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let rpc = client(socketPath: "/nonexistent.sock", tokenPath: path)
        await assertThrowsCode(.client) {
            _ = try await rpc.authorized(.status)
        }
    }

    func testRejectsOversizedTokenFile() async throws {
        let path = try writeTokenFile(String(repeating: "x", count: 5000))
        defer { try? FileManager.default.removeItem(atPath: path) }
        let rpc = client(socketPath: "/nonexistent.sock", tokenPath: path)
        await assertThrowsCode(.client) {
            _ = try await rpc.authorized(.status)
        }
    }

    // MARK: transport behavior

    func testRefusedConnectionIsTransportError() async throws {
        let rpc = client(
            socketPath: NSTemporaryDirectory()
                .appendingPathComponent("keylease-absent.sock"),
            tokenPath: try writeTokenFile()
        )
        await assertThrowsCode(.transport) {
            _ = try await rpc.unauthenticated(.status)
        }
    }

    func testOversizedResponseIsRejected() async throws {
        let daemon = try FakeDaemon { _ in
            .object(["ok": .bool(true),
                     "result": .string(String(repeating: "x", count: 5 << 20))])
        }
        defer { daemon.stop() }
        let rpc = client(
            socketPath: daemon.socketPath,
            tokenPath: try writeTokenFile()
        )
        await assertThrowsCode(.client) {
            _ = try await rpc.unauthenticated(.status)
        }
    }

    func testIncompleteResponseIsTransportError() async throws {
        // A daemon that closes without writing is not expressible through
        // FakeDaemon's responder, so use a raw socket that accepts then
        // closes.
        let path = NSTemporaryDirectory()
            .appendingPathComponent("keylease-test-\(UUID().uuidString).sock")
        let rpc = client(socketPath: path, tokenPath: try writeTokenFile())
        let closer = Thread {
            #if os(Linux)
                let streamType = Int32(SOCK_STREAM.rawValue)
            #else
                let streamType = SOCK_STREAM
            #endif
            let listener = socket(AF_UNIX, streamType, 0)
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            _ = withUnsafeMutablePointer(to: &address.sun_path) { ptr in
                path.withCString { cString in
                    strcpy(
                        UnsafeMutableRawPointer(ptr).assumingMemoryBound(
                            to: CChar.self
                        ), cString
                    )
                }
            }
            _ = withUnsafePointer(to: &address) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(listener, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            _ = listen(listener, 1)
            let conn = accept(listener, nil, nil)
            if conn >= 0 { close(conn) }
            close(listener)
        }
        closer.start()
        let deadline = Date().addingTimeInterval(2)
        while !FileManager.default.fileExists(atPath: path),
            Date() < deadline
        {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        await assertThrowsCode(.transport) {
            _ = try await rpc.unauthenticated(.status)
        }
        closer.cancel()
    }

    func testInvalidRequestEnvelopeMapsTypedCode() async throws {
        let golden = try loadGolden("22_invalid_request")
        let daemon = try FakeDaemon { _ in golden.response }
        defer { daemon.stop() }
        let rpc = client(
            socketPath: daemon.socketPath,
            tokenPath: try writeTokenFile()
        )
        await assertThrowsCode(.invalidRequest) {
            _ = try await rpc.authorized(.status)
        }
    }

    func testNonObjectResponseIsClientError() async throws {
        let daemon = try FakeDaemon { _ in .array([.string("nope")]) }
        defer { daemon.stop() }
        let rpc = client(
            socketPath: daemon.socketPath,
            tokenPath: try writeTokenFile()
        )
        await assertThrowsCode(.client) {
            _ = try await rpc.unauthenticated(.status)
        }
    }

    private func assertThrowsCode(
        _ code: KeyLeaseErrorCode,
        _ body: () async throws -> Void,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            try await body()
            XCTFail("expected KeyLeaseError(\(code))", file: file, line: line)
        } catch let error as KeyLeaseError {
            XCTAssertEqual(error.code, code, file: file, line: line)
        } catch {
            XCTFail("unexpected error \(error)", file: file, line: line)
        }
    }
}
