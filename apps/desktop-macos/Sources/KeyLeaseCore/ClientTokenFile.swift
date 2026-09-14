import Foundation

#if os(Linux)
    import Glibc
#else
    import Darwin
#endif

/// Reads and validates the registered client token file.
///
/// Same checks as `KeyLeaseRpc.auth()` in the Dart client: the path must be a
/// regular file (symlinks rejected via `lstat`), 1...4096 bytes, mode 0600 —
/// no group or other permission bits.
public enum ClientTokenFile {
    public static let maxBytes = 4096

    public static func read(at path: String) throws -> String {
        var st = stat()
        guard lstat(path, &st) == 0 else {
            throw KeyLeaseError(
                "Client token file is not readable: \(String(cString: strerror(errno)))"
            )
        }
        guard (st.st_mode & S_IFMT) == S_IFREG else {
            throw KeyLeaseError("Client token must be a regular file")
        }
        guard st.st_size > 0, st.st_size <= maxBytes else {
            throw KeyLeaseError("Client token file has an invalid size")
        }
        guard st.st_mode & 0o077 == 0 else {
            throw KeyLeaseError("Client token file must have mode 0600")
        }
        guard let data = FileManager.default.contents(atPath: path),
            let token = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
            !token.isEmpty
        else {
            throw KeyLeaseError("Client token is empty")
        }
        return token
    }
}
