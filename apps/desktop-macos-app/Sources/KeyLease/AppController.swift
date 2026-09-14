import Foundation

import KeyLeaseCore

/// `status` result — see `KeyLeaseService::status`.
struct VaultStatus: Sendable, Equatable {
    let locked: Bool
    let requiresUserAction: Bool
    let vaultId: String?
    let idleExpiresAt: String?

    init(_ json: JSONValue) {
        locked = json["locked"]?.boolValue ?? true
        requiresUserAction = json["requires_user_action"]?.boolValue ?? false
        vaultId = json["vault_id"]?.stringValue
        idleExpiresAt = json["idle_expires_at"]?.stringValue
    }
}

/// What the app is showing. Mirrors `AppPhase` in the Dart `AppController`,
/// minus the agent-handoff phases that need the full feature port.
enum AppPhase: Sendable, Equatable {
    case starting
    case onboarding
    case provisioning
    case repairRequired
    case backgroundApprovalRequired
    case serviceUnavailable
    case locked
    case permissionDenied
    case ready
}

/// A presentable problem. `UserMessage` in Dart carries diagnostics too;
/// milestone 1 keeps title + detail + a retry affordance.
struct UserMessage: Sendable, Equatable {
    let title: String
    let detail: String?

    init(title: String, detail: String? = nil) {
        self.title = title
        self.detail = detail
    }

    init(_ error: Error) {
        if let error = error as? KeyLeaseError {
            title = Self.title(for: error.code)
            detail = error.diagnostics
        } else if let error = error as? RuntimeError {
            title = error.message
            detail = error.code
        } else {
            title = "Something went wrong"
            detail = String(describing: error)
        }
    }

    static func title(for code: KeyLeaseErrorCode) -> String {
        switch code {
        case .vaultLocked: "The vault is locked"
        case .denied: "KeyLease denied this action"
        case .approvalRequired: "This action needs approval first"
        case .revisionConflict: "The vault changed underneath this action"
        case .notFound: "The item no longer exists"
        case .transport: "The KeyLease service is not reachable"
        case .crypto: "The master password was rejected"
        default: "Something went wrong"
        }
    }
}

/// Drives the app through inspect → service → status → ready, the same phase
/// machine as the Dart `AppController`.
@MainActor @Observable
final class AppController {
    private(set) var phase: AppPhase = .starting
    private(set) var status: VaultStatus?
    private(set) var vaultProfiles: [VaultProfile] = []
    private(set) var serviceVersion: String?
    var message: UserMessage?
    var unlockMessage: UserMessage?

    let runtime = RuntimeService()
    let security = SecurityService()
    let vault = VaultController()

    private var socketPath = ConnectionDefaults.socketPath
    private var tokenPath = ConnectionDefaults.tokenPath
    private let agentId = ConnectionDefaults.agentId

    private var client: KeyLeaseRpc {
        KeyLeaseRpc(
            socketPath: socketPath,
            agentId: agentId,
            tokenPath: tokenPath
        )
    }

    func bootstrap() async {
        phase = .starting
        message = nil
        do {
            let inspection = try await runtime.inspect()
            if let tokenPath = inspection.tokenPath {
                self.tokenPath = tokenPath
            }
            vaultProfiles = (try? await runtime.listVaults()) ?? []
            serviceVersion = inspection.serviceVersion
            switch inspection.state {
            case .needsOnboarding:
                enter(.onboarding)
                return
            case .repairRequired:
                enter(.repairRequired)
                return
            case .ready:
                try await runtime.ensureService()
                try await waitForService()
            }
        } catch {
            enter(
                (error as? RuntimeError)?.code == "BACKGROUND_APPROVAL_REQUIRED"
                    ? .backgroundApprovalRequired : .serviceUnavailable,
                UserMessage(error)
            )
            return
        }
        await refresh()
    }

    /// Recomputes the phase from the daemon — the Dart `refresh()`.
    func refresh() async {
        let raw: JSONValue
        do {
            raw = try await client.unauthenticated(.status)
        } catch let error as KeyLeaseError {
            enter(
                error.code == .client ? .repairRequired : .serviceUnavailable,
                UserMessage(error)
            )
            return
        } catch {
            enter(.serviceUnavailable, UserMessage(error))
            return
        }

        let next = VaultStatus(raw)
        status = next
        if next.locked {
            vault.clear()
            enter(
                .locked,
                UserMessage(
                    title: "Welcome back",
                    detail: "Unlock your vault to access your items."
                )
            )
            return
        }

        // Unlocked is not the same as allowed: probe one authorized read so a
        // policy denial surfaces as a denial, not as a locked vault.
        do {
            _ = try await client.authorized(.groupsList)
        } catch let error as KeyLeaseError {
            enter(
                switch error.code {
                case .denied: AppPhase.permissionDenied
                case .vaultLocked: AppPhase.locked
                case .client: AppPhase.repairRequired
                default: AppPhase.serviceUnavailable
                },
                UserMessage(error)
            )
            return
        } catch {
            enter(.serviceUnavailable, UserMessage(error))
            return
        }

        enter(.ready)
        await vault.load(using: client)
    }

    /// Polls `status` until the freshly started daemon accepts connections —
    /// the Dart `_waitForService` (30 × 100 ms).
    private func waitForService() async throws {
        var lastError: Error = RuntimeError.serviceNotFound
        for _ in 0..<30 {
            do {
                _ = try await client.unauthenticated(.status)
                return
            } catch {
                lastError = error
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
        }
        throw lastError
    }

    /// Returns true when the vault unlocked — same as the Dart signature so
    /// the onboarding "create first item" flow can chain off it.
    @discardableResult
    func unlock(_ password: String) async -> Bool {
        unlockMessage = nil
        do {
            _ = try await client.authorized(
                .unlock(
                    password: SecretValue(password),
                    sessionTtlSeconds: 900
                )
            )
            await refresh()
            return true
        } catch {
            unlockMessage = UserMessage(error)
            return false
        }
    }

    func lock() async {
        security.clearSensitiveClipboardIfUnchanged()
        _ = try? await client.authorized(.lock)
        vault.clear()
        await refresh()
    }

    /// `provision` with `{mode: "create"}` — milestone onboarding path.
    func provisionNewVault(password: String) async -> Bool {
        enter(.provisioning)
        do {
            try await runtime.provision(
                .object([
                    "mode": .string("create"),
                    "password": .string(password),
                ])
            )
            try await runtime.ensureService()
            try await waitForService()
            await refresh()
            return phase == .ready || phase == .locked
        } catch {
            enter(
                (error as? RuntimeError)?.code == "BACKGROUND_APPROVAL_REQUIRED"
                    ? .backgroundApprovalRequired : .onboarding,
                UserMessage(error)
            )
            return false
        }
    }

    /// `provision` with `{mode: "repair_desktop_client"}` — re-registers the
    /// desktop client token when the database exists but the token is gone.
    func repairClient(password: String) async -> Bool {
        enter(.provisioning)
        do {
            try await runtime.provision(
                .object([
                    "mode": .string("repair_desktop_client"),
                    "password": .string(password),
                ])
            )
            try await runtime.ensureService()
            try await waitForService()
            await refresh()
            return phase == .ready || phase == .locked
        } catch {
            enter(.repairRequired, UserMessage(error))
            return false
        }
    }

    func switchVault(id: String) async {
        do {
            let result = try await runtime.switchVault(id: id)
            if let tokenPath = result["token_path"]?.stringValue {
                self.tokenPath = tokenPath
            }
            status = nil
            vault.clear()
            try await runtime.ensureService()
            try await waitForService()
            await refresh()
        } catch {
            message = UserMessage(error)
        }
    }

    /// Screen lock and system sleep lock the vault — the Flutter
    /// `lockRequested` behaviour.
    func installLockObservers() {
        security.observeLockSignals { [weak self] in
            guard let self, self.phase == .ready else { return }
            Task { await self.lock() }
        }
    }

    private func enter(_ phase: AppPhase, _ message: UserMessage? = nil) {
        self.phase = phase
        self.message = message
    }
}
