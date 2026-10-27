import CryptoKit
import Foundation
import Security

import KeyLeaseCore

// The approver side of `keylease serve --approver-listen` (ADR 0005 mode B,
// docs/remote-approval.md): pair with a headless vault node using a one-time
// code, then list and decide its approvals with requests signed by this
// Mac's Ed25519 key. The node exposes no vault content to an approver.
//
// Profiles live in `~/.keylease/remotes/NAME.json` exactly as
// `keylease remote add` writes them, so the CLI and the app see the same
// remotes. A key paired from the app is kept in the login Keychain; a key
// paired from the CLI is read from its mode-0600 `NAME.key` file.

/// `~/.keylease/remotes/NAME.json` — the CLI's `RemoteProfile`.
private struct RemoteProfile: Codable {
    let url: String
    let deviceId: String

    private enum CodingKeys: String, CodingKey {
        case url
        case deviceId = "device_id"
    }
}

/// A paired remote vault node.
struct RemoteVault: Identifiable, Equatable, Sendable {
    enum KeySource: Sendable { case keychain, file }

    let name: String
    let url: String
    let deviceId: String
    let keySource: KeySource

    var id: String { name }

    var host: String { URL(string: url)?.host() ?? url }
}

enum RemoteApproverStore {
    private static let keychainService = "app.keylease.remote-approver"

    static var directory: URL {
        URL(fileURLWithPath: ConnectionDefaults.home)
            .appendingPathComponent(".keylease/remotes", isDirectory: true)
    }

    /// Same rule as the CLI's `valid_profile_name`.
    static func isValidName(_ name: String) -> Bool {
        !name.isEmpty && name.count <= 64
            && name.unicodeScalars.allSatisfy {
                ($0.isASCII && CharacterSet.alphanumerics.contains($0))
                    || $0 == "-" || $0 == "_"
            }
    }

    /// `https`, or `http` for a loopback address only (an SSH tunnel).
    static func validatedURL(_ raw: String) throws -> URL {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let host = url.host(),
            let scheme = url.scheme?.lowercased()
        else {
            throw KeyLeaseError("That is not a valid node URL.", code: .client)
        }
        let loopback = ["localhost", "127.0.0.1", "::1", "[::1]"]
            .contains(host.lowercased())
        guard scheme == "https" || (scheme == "http" && loopback) else {
            throw KeyLeaseError(
                "The node URL must use https (http only for localhost).",
                code: .client)
        }
        return url
    }

    static func list() -> [RemoteVault] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil)) ?? []
        return files
            .filter { $0.pathExtension == "json" }
            .compactMap { file -> RemoteVault? in
                let name = file.deletingPathExtension().lastPathComponent
                guard isValidName(name),
                    let data = try? Data(contentsOf: file),
                    let profile = try? JSONDecoder()
                        .decode(RemoteProfile.self, from: data)
                else { return nil }
                let source: RemoteVault.KeySource =
                    keychainSeed(name) != nil ? .keychain : .file
                return RemoteVault(
                    name: name, url: profile.url,
                    deviceId: profile.deviceId, keySource: source)
            }
            .sorted { $0.name < $1.name }
    }

    static func signingKey(for vault: RemoteVault) throws
        -> Curve25519.Signing.PrivateKey
    {
        let seed: Data
        switch vault.keySource {
        case .keychain:
            guard let stored = keychainSeed(vault.name) else {
                throw KeyLeaseError(
                    "The key for \(vault.name) is missing from the Keychain.",
                    code: .client)
            }
            seed = stored
        case .file:
            // Validates a regular, mode-0600 file like the CLI does.
            let encoded = try ClientTokenFile.read(
                at: directory.appendingPathComponent("\(vault.name).key").path)
            guard let decoded = Data(base64Encoded: encoded) else {
                throw KeyLeaseError(
                    "The key file for \(vault.name) is unreadable.",
                    code: .crypto)
            }
            seed = decoded
        }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    /// Stores a freshly paired remote. The key goes to the Keychain first so
    /// a profile never exists without its key.
    fileprivate static func save(
        name: String, profile: RemoteProfile,
        key: Curve25519.Signing.PrivateKey
    ) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try storeKeychainSeed(name, key.rawRepresentation)
        let data = try JSONEncoder().encode(profile)
        do {
            try data.write(
                to: directory.appendingPathComponent("\(name).json"),
                options: .withoutOverwriting)
        } catch {
            deleteKeychainSeed(name)
            throw error
        }
    }

    /// Forgets a remote on this Mac. Revoke the device on the node too
    /// (`keylease remote revoke-device`), or its key stays trusted there.
    static func remove(_ vault: RemoteVault) throws {
        let manager = FileManager.default
        try? manager.removeItem(
            at: directory.appendingPathComponent("\(vault.name).key"))
        deleteKeychainSeed(vault.name)
        try manager.removeItem(
            at: directory.appendingPathComponent("\(vault.name).json"))
    }

    static func exists(_ name: String) -> Bool {
        let manager = FileManager.default
        return manager.fileExists(
            atPath: directory.appendingPathComponent("\(name).json").path)
            || manager.fileExists(
                atPath: directory.appendingPathComponent("\(name).key").path)
            || keychainSeed(name) != nil
    }

    // MARK: Keychain

    private static func keychainQuery(_ name: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: name,
        ]
    }

    private static func keychainSeed(_ name: String) -> Data? {
        var query = keychainQuery(name)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess
        else { return nil }
        return result as? Data
    }

    private static func storeKeychainSeed(_ name: String, _ seed: Data) throws {
        var query = keychainQuery(name)
        query[kSecValueData as String] = seed
        query[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecAttrLabel as String] = "KeyLease approver key (\(name))"
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyLeaseError(
                "Could not store the approver key in the Keychain (\(status)).",
                code: .client)
        }
    }

    private static func deleteKeychainSeed(_ name: String) {
        SecItemDelete(keychainQuery(name) as CFDictionary)
    }
}

/// Body of `POST /v1/approvals/{id}/decide` (`DecideBody`).
private struct DecideBody: Encodable {
    let approve: Bool
    let requestDigestHex: String
    let policyVersion: UInt64
    let trust: TrustDecision?

    private enum CodingKeys: String, CodingKey {
        case approve
        case requestDigestHex = "request_digest_hex"
        case policyVersion = "policy_version"
        case trust
    }
}

/// Signed HTTP calls to one node's approver API.
struct RemoteApproverClient: Sendable {
    static let signatureContext = "KEYLEASE-APPROVER-V1"

    let vault: RemoteVault

    /// Pairs this Mac with a node using the code from
    /// `keylease remote pairing-code` on the node.
    static func pair(
        name: String, url rawURL: String, code: String, deviceName: String
    ) async throws -> RemoteVault {
        guard RemoteApproverStore.isValidName(name) else {
            throw KeyLeaseError(
                "Use letters, digits, '-' or '_' for the name.", code: .client)
        }
        guard !RemoteApproverStore.exists(name) else {
            throw KeyLeaseError(
                "A remote vault named \(name) already exists.", code: .client)
        }
        let base = try RemoteApproverStore.validatedURL(rawURL)
        let key = Curve25519.Signing.PrivateKey()
        let body = try JSONSerialization.data(withJSONObject: [
            "code": code.trimmingCharacters(in: .whitespacesAndNewlines),
            "name": deviceName,
            "public_key": key.publicKey.rawRepresentation.base64EncodedString(),
        ])
        var request = URLRequest(url: endpoint(base, "/v1/pair"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        let device = try await send(request)
        guard let deviceId = device["id"]?.stringValue else {
            throw KeyLeaseError("The node sent no device id.", code: .client)
        }
        try RemoteApproverStore.save(
            name: name,
            profile: RemoteProfile(url: base.absoluteString, deviceId: deviceId),
            key: key)
        return RemoteVault(
            name: name, url: base.absoluteString, deviceId: deviceId,
            keySource: .keychain)
    }

    func approvals() async throws -> [ApprovalRecord] {
        try await signed("GET", "/v1/approvals")
            .decoded(as: [ApprovalRecord].self)
    }

    func trusts() async throws -> [TrustRecord] {
        try await signed("GET", "/v1/trusts").decoded(as: [TrustRecord].self)
    }

    /// Binds the decision to the request as the node lists it now, so a
    /// request that changed since it was shown cannot be approved.
    func decide(
        _ approval: ApprovalRecord, approve: Bool, trust: TrustDecision?
    ) async throws {
        let current = try await approvals()
        guard let match = current.first(where: { $0.id == approval.id }),
            match.sameRequestAs(approval), match.decidableNow
        else {
            throw StaleApprovalError(
                message: "This request is no longer pending on \(vault.name).")
        }
        let body = try JSONEncoder().encode(
            DecideBody(
                approve: approve,
                requestDigestHex: match.requestDigestHex,
                policyVersion: match.policyVersion,
                trust: approve ? trust : nil))
        let id = try Self.pathSegment(approval.id)
        _ = try await signed("POST", "/v1/approvals/\(id)/decide", body: body)
    }

    func revokeTrust(_ trust: TrustRecord) async throws {
        let id = try Self.pathSegment(trust.id)
        _ = try await signed("POST", "/v1/trusts/\(id)/revoke")
    }

    // MARK: Transport

    /// `approver_signing_input`:
    /// `KEYLEASE-APPROVER-V1\nMETHOD\nPATH\nTIMESTAMP\nhex(sha256(body))`.
    static func signingInput(
        method: String, path: String, timestamp: Int64, body: Data
    ) -> Data {
        let digest = SHA256.hash(data: body)
            .map { String(format: "%02x", $0) }.joined()
        return Data(
            "\(signatureContext)\n\(method)\n\(path)\n\(timestamp)\n\(digest)"
                .utf8)
    }

    private func signed(_ method: String, _ path: String, body: Data = Data())
        async throws -> JSONValue
    {
        let key = try RemoteApproverStore.signingKey(for: vault)
        let base = try RemoteApproverStore.validatedURL(vault.url)
        let timestamp = Int64(Date().timeIntervalSince1970)
        let signature = try key.signature(
            for: Self.signingInput(
                method: method, path: path, timestamp: timestamp, body: body))
        var request = URLRequest(url: Self.endpoint(base, path))
        request.httpMethod = method
        request.setValue(vault.deviceId, forHTTPHeaderField: "X-KeyLease-Device")
        request.setValue(
            String(timestamp), forHTTPHeaderField: "X-KeyLease-Timestamp")
        request.setValue(
            signature.base64EncodedString(),
            forHTTPHeaderField: "X-KeyLease-Signature")
        if !body.isEmpty {
            request.setValue(
                "application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        return try await Self.send(request)
    }

    /// The node signs and routes on the absolute path, like the CLI's
    /// `Url::join("/v1/…")`: a path on the profile URL is replaced.
    private static func endpoint(_ base: URL, _ path: String) -> URL {
        URL(string: path, relativeTo: base)?.absoluteURL ?? base
    }

    private static func pathSegment(_ id: String) throws -> String {
        guard !id.isEmpty,
            id.unicodeScalars.allSatisfy({
                ($0.isASCII && CharacterSet.alphanumerics.contains($0))
                    || $0 == "_" || $0 == "-"
            })
        else {
            throw KeyLeaseError("Unexpected id from the node.", code: .client)
        }
        return id
    }

    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        return URLSession(configuration: configuration)
    }()

    private static func send(_ request: URLRequest) async throws -> JSONValue {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw KeyLeaseError.transport(error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let value = try? JSONDecoder().decode(JSONValue.self, from: data)
        guard (200..<300).contains(status) else {
            // The node answers errors with the daemon's error payload.
            if let value, value["error"] != nil {
                throw KeyLeaseError.fromDaemon(value)
            }
            throw KeyLeaseError.transport("The node answered HTTP \(status).")
        }
        guard let value else {
            throw KeyLeaseError.transport("The node sent an unreadable reply.")
        }
        return value
    }
}
