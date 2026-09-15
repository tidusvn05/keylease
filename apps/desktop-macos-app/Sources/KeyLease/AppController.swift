import AppKit
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
    /// An unmanaged vault left behind by an earlier install — onboarding
    /// offers to adopt it (`legacy_database` in `desktop inspect`).
    private(set) var legacyDatabase: String?
    var message: UserMessage?
    var unlockMessage: UserMessage?
    /// Transient copy confirmation shown as a floating capsule — every
    /// `copySensitive` call sites through here so the feedback is uniform.
    private(set) var copiedToast: String?
    private var toastTask: Task<Void, Never>?
    /// Top-level section shown in `ContentView` — lives here so the Go
    /// menu (⌘1–⌘5) can switch sections from outside the view tree.
    var section: AppSection = .vault
    /// Menu-bar quick access — status item + popover + ⌥⌘K hotkey.
    private var quickAccess: QuickAccessController?

    let runtime = RuntimeService()
    let security = SecurityService()
    let host = HostIntegrations()
    let preferences = PreferencesStore()
    let vault = VaultController()
    let connections = ConnectionsController()
    let approvals = ApprovalsController()
    let activity = ActivityController()

    var isReady: Bool { phase == .ready }

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
            legacyDatabase = inspection.legacyAvailable
                ? inspection.legacyDatabase : nil
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
            connections.list.clear()
            approvals.list.clear()
            activity.list.clear()
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
            let errorPhase = switch error.code {
            case .denied: AppPhase.permissionDenied
            case .vaultLocked: AppPhase.locked
            case .client: AppPhase.repairRequired
            default: AppPhase.serviceUnavailable
            }
            enter(errorPhase, UserMessage(error))
            return
        } catch {
            enter(.serviceUnavailable, UserMessage(error))
            return
        }

        enter(.ready)
        preferences.load()
        connections.use(client)
        approvals.use(client)
        activity.use(client)
        await vault.load(using: client)
        // The sidebar badge needs pending approvals without a visit to
        // the section — load once here, the section itself polls.
        Task { await approvals.list.load() }
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

    /// `provision` — create, import and repair modes all flow through the
    /// same call (`mode: create | adopt_keylease_database |
    /// restore_keylease_backup | import_kdbx | import_onepux |
    /// repair_desktop_client`), exactly like the Dart `provision`.
    @discardableResult
    func provision(_ request: JSONValue) async -> Bool {
        enter(.provisioning)
        do {
            try await runtime.provision(request)
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

    /// `provision` with `{mode: "create"}` — onboarding path for a fresh
    /// vault.
    func provisionNewVault(password: String) async -> Bool {
        await provision(.object([
            "mode": .string("create"),
            "password": .string(password),
        ]))
    }

    /// `NSOpenPanel` for a vault source (KDBX / 1PUX / KeyLease backup or
    /// database) — the Flutter `chooseVaultSource` channel call.
    func chooseVaultSource() -> String? {
        host.pickFile(
            title: "Choose a vault file",
            message: "Select a KeePass, 1Password, or KeyLease file to import."
        )?.path
    }

    /// `desktop inspect-source` — tells the onboarding form which import
    /// mode the chosen file needs.
    func inspectSource(path: String) async throws -> JSONValue {
        try await runtime.inspectSource(path: path)
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

    /// Installs the menu-bar status item, its quick-access popover and
    /// the ⌥⌘K hotkey that summons it from any app.
    func installQuickAccess() {
        guard quickAccess == nil else { return }
        let controller = QuickAccessController(app: self)
        controller.install()
        quickAccess = controller
    }

    // MARK: - Clipboard (`copySensitive` / agent prompt / CLI command)

    /// Copies a secret, schedules the conditional clear and confirms it
    /// on screen. Returns false for empty input, like the Dart adapter.
    @discardableResult
    func copySensitive(
        _ value: String, clearAfter seconds: Int = 30,
        label: String? = nil
    ) -> Bool {
        guard !value.isEmpty else { return false }
        security.copySensitive(value, clearAfter: seconds)
        copiedToast = (label ?? "Value") + " copied"
        toastTask?.cancel()
        toastTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.6))
            guard !Task.isCancelled else { return }
            self?.copiedToast = nil
        }
        return true
    }

    /// `agentPromptForEntry` — the instruction pasted into a local agent.
    static func agentPromptForEntry(_ entry: ItemMetadata) -> String {
        let quoted = (try? JSONEncoder().encode(entry.title))
            .map { String(decoding: $0, as: UTF8.self) }
            ?? "\"\(entry.title)\""
        let readInstructions = entry.isAgentContent
            ? "Read its content: `keylease content get \(entry.id) --raw`\n"
                + "If access is denied, ask me to grant this agent read access."
            : "Inspect it: `keylease entries get \(entry.id)`\n"
                + "List its fields: `keylease entries view \(entry.id)`\n"
                + "Reveal only a needed field: `keylease entries reveal "
                + "\(entry.id) --field <field-id>`\n"
                + "Get its OTP if needed: `keylease entries totp \(entry.id)`"
        return """
            Use KeyLease Vault item \(quoted) (`\(entry.id)`) for this task.

            Connect to KeyLease directly; do not ask me to paste the item content.
            \(readInstructions)

            Keep returned content and secrets private. If the vault is locked, \
            ask me to unlock KeyLease.
            """
    }

    /// `cliCommandForEntry` — the one-liner copied to the clipboard.
    static func cliCommandForEntry(_ entry: ItemMetadata) -> String {
        entry.isAgentContent
            ? "keylease content get \(entry.id) --raw"
            : "keylease entries get \(entry.id)"
    }

    @discardableResult
    func copyAgentPrompt(_ entry: ItemMetadata) -> Bool {
        copySensitive(
            Self.agentPromptForEntry(entry), clearAfter: 120,
            label: "Agent prompt")
    }

    @discardableResult
    func copyCliCommand(_ entry: ItemMetadata) -> Bool {
        copySensitive(
            Self.cliCommandForEntry(entry), clearAfter: 120,
            label: "CLI command")
    }

    // MARK: - Preferences passthroughs

    var passwordGeneratorSettings: PasswordGeneratorSettings {
        preferences.passwordGenerator
    }

    func updatePasswordGeneratorSettings(_ value: PasswordGeneratorSettings) {
        preferences.passwordGenerator = value
    }

    /// `sshKeyBinding` — the per-device private key bound to an SSH
    /// endpoint (stored under `~/.keylease/ui.json`, never in the vault).
    func sshKeyBinding(itemId: String, endpointId: String) -> String? {
        preferences.sshKeyBinding(
            itemId: itemId, endpointId: endpointId,
            vaultId: status?.vaultId)
    }

    func setSshKeyBinding(
        _ itemId: String, _ endpointId: String, _ path: String?
    ) throws {
        try preferences.setSshKeyBinding(
            itemId: itemId, endpointId: endpointId,
            vaultId: status?.vaultId, path: path)
    }

    func removeSshBindingsForItem(_ itemId: String) {
        preferences.removeSshBindingsForItem(itemId)
    }

    // MARK: - Managed vaults (`desktop vault-*` helper commands)

    /// `desktop vault-create` — `request` is the tagged provision payload
    /// (`mode: create | adopt_* | restore_* | import_*`).
    func createManagedVault(name: String, request: JSONValue) async throws {
        try await runtime.createVault(.object([
            "name": .string(name),
            "request": request,
        ]))
        vaultProfiles = (try? await runtime.listVaults()) ?? vaultProfiles
    }

    func renameManagedVault(_ id: String, name: String) async throws {
        try await runtime.renameVault(id: id, name: name)
        vaultProfiles = (try? await runtime.listVaults()) ?? vaultProfiles
    }

    /// `switchManagedVault` — locks, switches, restarts and refreshes; on
    /// failure the previous vault is restored (the Dart rollback path).
    func switchManagedVault(_ id: String) async {
        let previous = vaultProfiles.first(where: \.active)
        if previous?.id == id { return }
        if isReady { await lock() }
        vault.clear()
        do {
            let result = try await runtime.switchVault(id: id)
            if let tokenPath = result["token_path"]?.stringValue {
                self.tokenPath = tokenPath
            }
            try await runtime.ensureService(restart: true)
            let inspection = try await runtime.inspect()
            if let tokenPath = inspection.tokenPath {
                self.tokenPath = tokenPath
            }
            vaultProfiles = (try? await runtime.listVaults()) ?? vaultProfiles
            try await waitForService()
            await refresh()
        } catch {
            if let previous {
                _ = try? await runtime.switchVault(id: previous.id)
                try? await runtime.ensureService(restart: true)
                if let inspection = try? await runtime.inspect(),
                    let tokenPath = inspection.tokenPath
                {
                    self.tokenPath = tokenPath
                }
                vaultProfiles =
                    (try? await runtime.listVaults()) ?? vaultProfiles
            }
            message = UserMessage(error)
        }
    }

    /// Restarts the LaunchAgent (or detached dev daemon) then refreshes.
    func restartService() async {
        do {
            try await runtime.ensureService(restart: true)
            try await waitForService()
            await refresh()
        } catch {
            message = UserMessage(error)
        }
    }

    func openDataFolder() {
        _ = runtime.openDataFolder()
    }

    func clearUnlockMessage() {
        unlockMessage = nil
    }

    private func enter(_ phase: AppPhase, _ message: UserMessage? = nil) {
        self.phase = phase
        self.message = message
    }
}
