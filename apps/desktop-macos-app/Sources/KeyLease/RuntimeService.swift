import AppKit
import Darwin
import Foundation
import ServiceManagement

import KeyLeaseCore

/// Errors from the local runtime layer — the values carried by the Flutter
/// `com.keylease/runtime` channel, kept so behaviour matches 1:1.
struct RuntimeError: Error, Equatable, Sendable {
    let code: String
    let message: String

    static let helperMissing = RuntimeError(
        code: "HELPER_MISSING", message: "KeyLease runtime is missing")
    static let helperFailed = RuntimeError(
        code: "HELPER_FAILED", message: "KeyLease could not complete setup")
    static let invalidResponse = RuntimeError(
        code: "INVALID_HELPER_RESPONSE",
        message: "The KeyLease runtime returned an unreadable response")
    static let backgroundApprovalRequired = RuntimeError(
        code: "BACKGROUND_APPROVAL_REQUIRED",
        message: "Allow KeyLease in Login Items")
    static let serviceNotFound = RuntimeError(
        code: "SERVICE_NOT_FOUND",
        message: "The bundled KeyLease background service was not found")
    static func registrationFailed(_ error: NSError) -> RuntimeError {
        RuntimeError(
            code: "SERVICE_REGISTRATION_FAILED",
            message: "Could not enable KeyLease in the background "
                + "(\(error.domain) \(error.code))")
    }
}

/// `keylease desktop inspect` result. See `DesktopCommand::Inspect`.
struct LocalRuntimeInspection: Sendable, Equatable {
    enum State: String, Sendable {
        case needsOnboarding = "needs_onboarding"
        case ready = "ready"
        case repairRequired = "repair_required"
    }

    let state: State
    let legacyAvailable: Bool
    let legacyDatabase: String?
    let serviceVersion: String?
    let tokenPath: String?

    init(_ json: JSONValue) {
        let raw = json["state"]?.stringValue ?? "needs_onboarding"
        state = State(rawValue: raw) ?? .needsOnboarding
        legacyAvailable = json["legacy_available"]?.boolValue ?? false
        legacyDatabase = json["legacy_database"]?.stringValue
        serviceVersion = json["service_version"]?.stringValue
        tokenPath = json["token_path"]?.stringValue
    }
}

/// One profile in `keylease desktop vaults-list`.
struct VaultProfile: Sendable, Equatable, Identifiable {
    let id: String
    let name: String
    let active: Bool
}

/// Runs the bundled `keylease` binary and manages the LaunchAgent daemon.
///
/// Port of `LocalRuntimeBridge` in the Flutter runner's
/// `MainFlutterWindow.swift`. CLI calls are identical; the MethodChannel hop
/// disappears because the app is native now.
final class RuntimeService: Sendable {
    /// Resolution order: `$KEYLEASE_HELPER` (development), the bundled
    /// `Contents/Resources/keylease`, then the CLI install location used by
    /// `build-install-macos.sh`.
    func helperURL() -> URL? {
        if let override = ProcessInfo.processInfo.environment["KEYLEASE_HELPER"],
            FileManager.default.isExecutableFile(atPath: override)
        {
            return URL(fileURLWithPath: override)
        }
        if let bundled = Bundle.main.resourceURL?.appendingPathComponent("keylease"),
            FileManager.default.isExecutableFile(atPath: bundled.path)
        {
            return bundled
        }
        let installed = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin/keylease")
        if FileManager.default.isExecutableFile(atPath: installed.path) {
            return installed
        }
        return nil
    }

    /// True when running from a real .app bundle; `swift run` in development
    /// is not bundled, and SMAppService cannot see its LaunchAgents there.
    private var isBundled: Bool {
        Bundle.main.bundleURL.pathExtension == "app"
    }

    // MARK: - CLI calls (same argument lists as the Flutter bridge)

    func inspect() async throws -> LocalRuntimeInspection {
        LocalRuntimeInspection(try await run(["desktop", "inspect"]))
    }

    func inspectSource(path: String) async throws -> JSONValue {
        try await run(["desktop", "inspect-source", path])
    }

    func provision(_ request: JSONValue) async throws {
        let data = try JSONEncoder().encode(request)
        _ = try await run(["desktop", "provision"], input: data)
    }

    func listVaults() async throws -> [VaultProfile] {
        let registry = try await run(["desktop", "vaults-list"])
        let activeId = registry["active_id"]?.stringValue
        return registry["profiles"]?.arrayValue?.compactMap { item in
            guard let id = item["id"]?.stringValue else { return nil }
            return VaultProfile(
                id: id,
                name: item["name"]?.stringValue ?? id,
                active: id == activeId
            )
        } ?? []
    }

    func createVault(_ request: JSONValue) async throws {
        let data = try JSONEncoder().encode(request)
        _ = try await run(["desktop", "vault-create"], input: data)
    }

    func switchVault(id: String) async throws -> JSONValue {
        try await run(["desktop", "vault-switch", id])
    }

    func renameVault(id: String, name: String) async throws {
        _ = try await run(["desktop", "vault-rename", id, name])
    }

    /// The bridge returned `nil` for provision/switch-style calls; keeping a
    /// discardable JSONValue here preserves the stdout check for free.
    @discardableResult
    private func run(
        _ arguments: [String], input: Data? = nil
    ) async throws -> JSONValue {
        guard let executable = helperURL() else {
            throw RuntimeError.helperMissing
        }
        let process = Process()
        let output = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        if let input {
            let stdin = Pipe()
            process.standardInput = stdin
            do {
                try process.run()
                stdin.fileHandleForWriting.write(input)
                try? stdin.fileHandleForWriting.close()
            } catch {
                throw RuntimeError.helperFailed
            }
        } else {
            do {
                try process.run()
            } catch {
                throw RuntimeError.helperFailed
            }
        }
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            throw RuntimeError.helperFailed
        }
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: data)
        else {
            throw RuntimeError.invalidResponse
        }
        return value
    }

    // MARK: - Background service

    /// Registers the bundled LaunchAgent, or — when running unbundled under
    /// `swift run` — spawns `keylease desktop serve` detached so the socket
    /// comes up without launchd. A detached dev daemon outlives the app;
    /// kill it manually when done.
    func ensureService(restart: Bool = false) async throws {
        if isBundled {
            try ensureBundledService(restart: restart)
        } else if restart || !socketResponds() {
            try spawnDetachedDaemon()
        }
    }

    private func ensureBundledService(restart: Bool) throws {
        let service = SMAppService.agent(
            plistName: "app.keylease.service.plist")
        do {
            if restart,
                service.status == .enabled
                    || service.status == .requiresApproval
            {
                try service.unregister()
            }
            if service.status == .notRegistered || service.status == .notFound {
                try service.register()
            }
        } catch {
            throw RuntimeError.registrationFailed(error as NSError)
        }
        switch service.status {
        case .enabled:
            return
        case .requiresApproval:
            throw RuntimeError.backgroundApprovalRequired
        default:
            throw RuntimeError.serviceNotFound
        }
    }

    /// Connect-only probe: a listening daemon accepts the connection, which
    /// is enough for "is the service up" without framing a request.
    private func socketResponds() -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = ConnectionDefaults.socketPath
        guard path.utf8.count < MemoryLayout.size(ofValue: address.sun_path)
        else { return false }
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
        return withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
    }

    private func spawnDetachedDaemon() throws {
        guard let executable = helperURL() else {
            throw RuntimeError.helperMissing
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = ["desktop", "serve"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        // Reap the child on exit so a dead daemon never lingers as a zombie.
        process.terminationHandler = { _ in }
        do {
            try process.run()
        } catch {
            throw RuntimeError.helperFailed
        }
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    func openDataFolder() -> Bool {
        let folder = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".keylease")
        try? FileManager.default.createDirectory(
            at: folder, withIntermediateDirectories: true)
        return NSWorkspace.shared.open(folder)
    }
}
