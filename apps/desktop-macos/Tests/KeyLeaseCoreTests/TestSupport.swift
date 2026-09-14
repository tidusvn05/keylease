import Foundation
import XCTest

#if os(Linux)
    import Glibc
#else
    import Darwin
#endif

@testable import KeyLeaseCore

/// Repository root, resolved relative to this source file so tests work from
/// any checkout directory on macOS and Linux alike.
let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // KeyLeaseCoreTests/
    .deletingLastPathComponent()  // Tests/
    .deletingLastPathComponent()  // desktop-macos/
    .deletingLastPathComponent()  // apps/
    .deletingLastPathComponent()  // repo root

let rpcTestVectors = repositoryRoot
    .appendingPathComponent("test-vectors/rpc")

func loadGolden(_ name: String) throws -> (
    request: JSONValue, response: JSONValue
) {
    let url = rpcTestVectors
        .appendingPathComponent("golden/\(name).json")
    let pair = try JSONDecoder().decode(
        [String: JSONValue].self,
        from: Data(contentsOf: url)
    )
    guard let request = pair["request"], let response = pair["response"] else {
        throw NSError(
            domain: "KeyLeaseCoreTests", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "malformed vector \(name)"]
        )
    }
    return (request, response)
}

/// Writes a fake client token file and returns its path.
@discardableResult
func writeTokenFile(
    _ contents: String = "<redacted-client-token>",
    mode: mode_t = 0o600
) throws -> String {
    let path = NSTemporaryDirectory()
        .appendingPathComponent("keylease-test-\(UUID().uuidString).token")
    try contents.write(toFile: path, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes(
        [.posixPermissions: NSNumber(value: Int(mode))],
        ofItemAtPath: path
    )
    return path
}

/// A throwaway Unix-socket server that answers one line-delimited JSON
/// request per connection — enough to stand in for `keylease serve`.
final class FakeDaemon: @unchecked Sendable {
    let socketPath: String
    private var listener: Int32 = -1
    private var worker: Thread?
    private var stopped = false
    private let stateLock = NSLock()
    private var recorded: [JSONValue] = []

    /// Maps a decoded request to the raw response object written back.
    var responder: (JSONValue) -> JSONValue

    init(responder: @escaping (JSONValue) -> JSONValue) throws {
        self.responder = responder
        socketPath = NSTemporaryDirectory()
            .appendingPathComponent(
                "keylease-test-\(UUID().uuidString).sock"
            )
        #if os(Linux)
            let streamType = Int32(SOCK_STREAM.rawValue)
        #else
            let streamType = SOCK_STREAM
        #endif
        listener = socket(AF_UNIX, streamType, 0)
        guard listener >= 0 else {
            throw POSIXError(.EIO)
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &address.sun_path) { ptr in
            socketPath.withCString { cString in
                strcpy(
                    UnsafeMutableRawPointer(ptr).assumingMemoryBound(
                        to: CChar.self
                    ),
                    cString
                )
            }
        }
        let bound = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(listener, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(listener, 8) == 0 else {
            throw POSIXError(.EIO)
        }
        worker = Thread { [self] in acceptLoop() }
        worker?.start()
    }

    var requests: [JSONValue] {
        stateLock.lock()
        defer { stateLock.unlock() }
        return recorded
    }

    private func acceptLoop() {
        while true {
            stateLock.lock()
            let done = stopped
            stateLock.unlock()
            if done { return }

            var pollFd = pollfd(
                fd: listener, events: Int16(POLLIN), revents: 0
            )
            guard poll(&pollFd, 1, 100) > 0 else { continue }
            let conn = accept(listener, nil, nil)
            guard conn >= 0 else { continue }
            handle(conn)
            close(conn)
        }
    }

    private func handle(_ conn: Int32) {
        // Same SIGPIPE rule as the client: a test that closes early must
        // produce EPIPE here, not kill the test runner.
        #if os(Linux)
            let sendFlags = Int32(MSG_NOSIGNAL)
        #else
            let sendFlags: Int32 = 0
            var noSigPipe: Int32 = 1
            _ = setsockopt(
                conn, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                socklen_t(MemoryLayout<Int32>.size)
            )
        #endif
        var bytes = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while bytes.last != 0x0A, bytes.count < 8 * 1024 * 1024 {
            let received = recv(conn, &chunk, chunk.count, 0)
            if received < 0 && errno == EINTR { continue }
            guard received > 0 else { return }
            bytes.append(contentsOf: chunk[..<received])
        }
        guard
            let request = try? JSONDecoder().decode(
                JSONValue.self,
                from: Data(bytes.dropLast())
            )
        else { return }
        stateLock.lock()
        recorded.append(request)
        stateLock.unlock()
        var response = (try? JSONEncoder().encode(responder(request)))
            ?? Data()
        response.append(0x0A)
        response.withUnsafeBytes { buf in
            var sent = 0
            while sent < buf.count {
                let written = send(
                    conn, buf.baseAddress!.advanced(by: sent),
                    buf.count - sent, sendFlags
                )
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { return }
                sent += written
            }
        }
    }

    func stop() {
        stateLock.lock()
        stopped = true
        stateLock.unlock()
        if let worker, !worker.isFinished {
            let deadline = Date().addingTimeInterval(5)
            while !worker.isFinished, Date() < deadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
        }
        close(listener)
        try? FileManager.default.removeItem(atPath: socketPath)
    }

    deinit { stop() }
}
