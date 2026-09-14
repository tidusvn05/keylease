import Foundation

#if os(Linux)
    import Glibc
#else
    import Darwin
#endif

/// Indirection so state and feature code can be tested without a daemon,
/// matching `KeyLeaseClient` in the Dart shared package.
public protocol KeyLeaseClient: Sendable {
    /// Sends `request` with a freshly read `auth` block.
    func authorized(_ request: RpcRequest) async throws -> JSONValue

    /// Sends `request` without an `auth` block. Only `status` qualifies.
    func unauthenticated(_ request: RpcRequest) async throws -> JSONValue
}

/// Line-delimited JSON client for the local KeyLease unix socket.
///
/// One connection per call, bounded to 4 MiB in each direction — the same
/// transport semantics as `keylease_rpc.dart`.
public struct KeyLeaseRpc: KeyLeaseClient {
    public let socketPath: String
    public let agentId: String
    public let tokenPath: String
    public let sessionId: String

    public static let maxMessageBytes = 4 * 1024 * 1024
    public static let connectTimeout: TimeInterval = 10
    public static let responseTimeout: TimeInterval = 30

    public init(
        socketPath: String,
        agentId: String,
        tokenPath: String,
        sessionId: String = "desktop"
    ) {
        self.socketPath = socketPath
        self.agentId = agentId
        self.tokenPath = tokenPath
        self.sessionId = sessionId
    }

    /// Builds the `auth` block, re-reading the token file on every call so a
    /// rotated token is picked up without restarting the app.
    public func auth() throws -> RpcAuth {
        guard !agentId.trimmingCharacters(in: .whitespaces).isEmpty,
            !tokenPath.trimmingCharacters(in: .whitespaces).isEmpty
        else {
            throw KeyLeaseError("Client ID and token file are required")
        }
        return RpcAuth(
            agentId: agentId.trimmingCharacters(in: .whitespaces),
            token: SecretValue(try ClientTokenFile.read(at: tokenPath)),
            sessionId: sessionId
        )
    }

    public func authorized(_ request: RpcRequest) async throws -> JSONValue {
        try await call(request, auth: auth())
    }

    public func unauthenticated(_ request: RpcRequest) async throws -> JSONValue {
        try await call(request, auth: nil)
    }

    public func call(_ request: RpcRequest, auth: RpcAuth?) async throws
        -> JSONValue
    {
        let line = try encodeLine(request, auth: auth)
        let responseData = try await Self.roundTrip(
            socketPath: socketPath,
            payload: line
        )
        let response: JSONValue
        do {
            response = try JSONDecoder().decode(
                JSONValue.self, from: responseData
            )
        } catch {
            throw KeyLeaseError("Invalid local IPC response")
        }
        guard case .object(let object) = response else {
            throw KeyLeaseError("Invalid local IPC response")
        }
        if object["ok"] == .bool(false) {
            throw KeyLeaseError.fromDaemon(object["error"] ?? .null)
        }
        return object["result"] ?? .null
    }

    /// `{"command": ..., "auth": ..., ...}` plus a trailing newline.
    func encodeLine(_ request: RpcRequest, auth: RpcAuth?) throws -> Data {
        let requestData = try JSONEncoder().encode(request)
        guard var object = try JSONSerialization.jsonObject(
            with: requestData
        ) as? [String: Any] else {
            throw KeyLeaseError("Could not encode request")
        }
        if let auth {
            let authData = try JSONEncoder().encode(auth)
            object["auth"] = try JSONSerialization.jsonObject(with: authData)
        }
        var data = try JSONSerialization.data(withJSONObject: object)
        data.append(0x0A)
        // Same bound as the Dart client: the limit applies to the framed
        // line including the terminator, and exactly 4 MiB is still legal.
        guard data.count <= Self.maxMessageBytes else {
            throw KeyLeaseError("Request exceeds the local IPC size limit")
        }
        return data
    }

    /// Blocking POSIX round-trip, pushed off the cooperative executor.
    static func roundTrip(socketPath: String, payload: Data) async throws
        -> Data
    {
        try await Task.detached {
            try UnixSocket.roundTrip(
                path: socketPath,
                payload: payload,
                connectTimeout: connectTimeout,
                responseTimeout: responseTimeout,
                maxBytes: maxMessageBytes
            )
        }.value
    }
}

/// Minimal AF_UNIX client. POSIX sockets keep this file identical on macOS
/// and Linux, so the transport is exercised by `swift test` on CI machines
/// without a Darwin SDK.
enum UnixSocket {
    static func roundTrip(
        path: String,
        payload: Data,
        connectTimeout: TimeInterval,
        responseTimeout: TimeInterval,
        maxBytes: Int
    ) throws -> Data {
        #if os(Linux)
            let streamType = Int32(SOCK_STREAM.rawValue)
        #else
            let streamType = SOCK_STREAM
        #endif
        let fd = socket(AF_UNIX, streamType, 0)
        guard fd >= 0 else {
            throw KeyLeaseError.transport(
                "socket: \(String(cString: strerror(errno)))"
            )
        }
        defer { close(fd) }

        // A daemon that closes mid-request must surface as a transport
        // error, not a process-killing SIGPIPE. Darwin has no MSG_NOSIGNAL
        // send flag, so it gets the equivalent socket option instead.
        #if os(Linux)
            let sendFlags = Int32(MSG_NOSIGNAL)
        #else
            let sendFlags: Int32 = 0
            var noSigPipe: Int32 = 1
            _ = setsockopt(
                fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                socklen_t(MemoryLayout<Int32>.size)
            )
        #endif

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let maxPath = MemoryLayout.size(ofValue: address.sun_path)
        guard path.utf8.count < maxPath else {
            throw KeyLeaseError.transport("Socket path is too long")
        }
        _ = withUnsafeMutablePointer(to: &address.sun_path) { ptr in
            path.withCString { cString in
                strcpy(
                    UnsafeMutableRawPointer(ptr).assumingMemoryBound(
                        to: CChar.self
                    ),
                    cString
                )
            }
        }

        // Non-blocking connect so a wedged listener cannot hang the client
        // past the connect timeout.
        let flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let connectResult = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(
                to: sockaddr.self, capacity: 1
            ) { sockaddrPtr in
                connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        // EINTR leaves the connection attempt running; poll for it like
        // EINPROGRESS rather than failing on a stray signal.
        if connectResult != 0 && (errno == EINPROGRESS || errno == EINTR) {
            var pollFd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            var ready: Int32
            repeat {
                ready = poll(&pollFd, 1, Int32(connectTimeout * 1000))
            } while ready < 0 && errno == EINTR
            guard ready != 0 else {
                throw KeyLeaseError.transport("Timed out connecting to daemon")
            }
            guard ready > 0 else {
                throw KeyLeaseError.transport(
                    "poll: \(String(cString: strerror(errno)))"
                )
            }
            var socketError: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            _ = getsockopt(
                fd, SOL_SOCKET, SO_ERROR, &socketError, &length
            )
            guard socketError == 0 else {
                throw KeyLeaseError.transport(
                    "connect: \(String(cString: strerror(socketError)))"
                )
            }
        } else if connectResult != 0 {
            throw KeyLeaseError.transport(
                "connect: \(String(cString: strerror(errno)))"
            )
        }
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)

        var timeout = timeval(
            tv_sec: Int(responseTimeout),
            tv_usec: 0
        )
        _ = setsockopt(
            fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        _ = setsockopt(
            fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )

        try payload.withUnsafeBytes { buffer in
            var sent = 0
            while sent < payload.count {
                let written = send(
                    fd, buffer.baseAddress!.advanced(by: sent),
                    payload.count - sent, sendFlags
                )
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else {
                    throw KeyLeaseError.transport(
                        "send: \(String(cString: strerror(errno)))"
                    )
                }
                sent += written
            }
        }

        var response = Data()
        response.reserveCapacity(4096)
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        var complete = false
        while !complete {
            let received = recv(fd, &chunk, chunk.count, 0)
            if received < 0 && errno == EINTR { continue }
            guard received > 0 else {
                if received == 0 {
                    throw KeyLeaseError.transport(
                        "Incomplete local IPC response"
                    )
                }
                throw KeyLeaseError.transport(
                    "recv: \(String(cString: strerror(errno)))"
                )
            }
            for byte in chunk[..<received] {
                if byte == 0x0A {
                    complete = true
                    break
                }
                response.append(byte)
                if response.count > maxBytes {
                    throw KeyLeaseError(
                        "Response exceeds the local IPC size limit"
                    )
                }
            }
        }
        return response
    }
}
