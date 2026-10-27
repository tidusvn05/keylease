import AppKit
import Foundation

import KeyLeaseCore

/// `status` result — see `KeyLeaseService::status`.
struct VaultStatus: Sendable, Equatable {
    let locked: Bool
    let requiresUserAction: Bool
    let vaultId: String?
    let idleExpiresAt: String?
    /// Pending approvals, counted by the daemon. Polling `status` for it
    /// neither extends the idle timeout nor writes audit.
    let pendingApprovals: Int?

    init(_ json: JSONValue) {
        locked = json["locked"]?.boolValue ?? true
        requiresUserAction = json["requires_user_action"]?.boolValue ?? false
        vaultId = json["vault_id"]?.stringValue
        idleExpiresAt = json["idle_expires_at"]?.stringValue
        pendingApprovals = json["pending_approvals"]?.intValue.map(Int.init)
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

/// Wraps a `KeyLeaseClient` and reports `vault_locked` rejections, so the
/// app can drop to the lock screen no matter which feature issued the
/// RPC — an idle daemon timeout otherwise leaves dead vault data on
/// screen with every action failing.
struct LockAwareClient: KeyLeaseClient {
    let base: KeyLeaseClient
    let onVaultLocked: @MainActor @Sendable () -> Void

    func authorized(_ request: RpcRequest) async throws -> JSONValue {
        do {
            return try await base.authorized(request)
        } catch let error as KeyLeaseError where error.code == .vaultLocked {
            await onVaultLocked()
            throw error
        }
    }

    func unauthenticated(_ request: RpcRequest) async throws -> JSONValue {
        try await base.unauthenticated(request)
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
    /// menu (⌘1–⌘6) can switch sections from outside the view tree.
    var section: AppSection = .vault
    /// Menu-bar quick access — status item + popover + ⌥⌘K hotkey.
    private var quickAccess: QuickAccessController?
    /// The app's main window, tracked by `WindowAccessor` in `RootView`
    /// so "open in app" reuses it rather than opening a duplicate.
    weak var mainWindow: NSWindow?

    let runtime = RuntimeService()
    let security = SecurityService()
    let host = HostIntegrations()
    let preferences = PreferencesStore()
    let vault = VaultController()
    let connections = ConnectionsController()
    let approvals = ApprovalsController()
    let trusts = TrustsController()
    let remotes = RemoteVaultsController()
    let activity = ActivityController()
    let notifier = ApprovalNotifier()
    /// Pending local approvals from the last `status` poll.
    private(set) var localPendingApprovals = 0

    var isReady: Bool { phase == .ready }

    private var socketPath = ConnectionDefaults.socketPath
    private var tokenPath = ConnectionDefaults.tokenPath
    private let agentId = ConnectionDefaults.agentId

    /// One-shot check armed for the daemon's `idle_expires_at` — sees the
    /// auto-lock the moment it happens instead of the next failed RPC.
    private var idleWatchTask: Task<Void, Never>?
    /// Debounces `handleSessionLocked` — a burst of in-flight RPCs can all
    /// fail `vault_locked` at once but only one refresh should run.
    private var sessionLockCheck: Task<Void, Never>?
    /// Watches for new approval requests while the vault is open.
    private var approvalWatchTask: Task<Void, Never>?

    private var client: KeyLeaseRpc {
        KeyLeaseRpc(
            socketPath: socketPath,
            agentId: agentId,
            tokenPath: tokenPath
        )
    }

    /// The client handed to feature controllers — `vault_locked` replies
    /// route through `handleSessionLocked` before reaching the caller.
    private var monitoredClient: KeyLeaseClient {
        LockAwareClient(base: client) { [weak self] in
            self?.handleSessionLocked()
        }
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
        scheduleIdleWatch(next)
        if next.locked {
            vault.clear()
            connections.list.clear()
            approvals.list.clear()
            trusts.clear()
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
        connections.use(monitoredClient)
        approvals.use(monitoredClient)
        trusts.use(monitoredClient)
        activity.use(monitoredClient)
        await vault.load(using: monitoredClient)
        localPendingApprovals = next.pendingApprovals ?? 0
        // Notify about requests already waiting, then watch for new ones.
        Task {
            await approvals.list.load()
            notifier.notify(approvals.list.items, source: nil)
        }
        startApprovalWatch()
    }

    // MARK: - Approval watch and notifications (ADR 0005)

    func installApprovalNotifications() {
        notifier.install()
        notifier.onOpen = { [weak self] remote in
            guard let self, self.phase == .ready else { return }
            self.section = remote == nil ? .approvals : .remoteVaults
            self.mainWindow?.makeKeyAndOrderFront(nil)
        }
        remotes.onApprovals = { [weak self] approvals, remote in
            self?.notifier.notify(approvals, source: remote)
            self?.notifier.retire(keeping: approvals, source: remote)
            self?.updateDockBadge()
        }
    }

    /// Polls `status` every 5 s for the pending count — it is the cheap,
    /// passive read — and reloads the list only when a request arrives.
    /// Paired remote nodes are polled every 15 s.
    private func startApprovalWatch() {
        guard approvalWatchTask == nil else { return }
        approvalWatchTask = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                guard let app = self, app.phase == .ready else { return }
                await app.pollApprovals(includeRemotes: tick % 3 == 0)
                tick += 1
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    private func stopApprovalWatch() {
        approvalWatchTask?.cancel()
        approvalWatchTask = nil
        localPendingApprovals = 0
        updateDockBadge()
    }

    private func pollApprovals(includeRemotes: Bool) async {
        if let raw = try? await client.unauthenticated(.status) {
            let next = VaultStatus(raw)
            if next.locked {
                handleSessionLocked()
                return
            }
            let pending = next.pendingApprovals ?? 0
            let arrived = pending > localPendingApprovals
            localPendingApprovals = pending
            if arrived {
                // An authorized read, so only on arrival: every reload
                // counts as vault activity and is audited.
                await approvals.list.load()
                notifier.notify(approvals.list.items, source: nil)
            } else if pending == 0 {
                notifier.retire(keeping: [], source: nil)
            }
        }
        if includeRemotes {
            await remotes.refreshAll()
        }
        updateDockBadge()
    }

    private func updateDockBadge() {
        let total = localPendingApprovals + remotes.pendingCount
        NSApp.dockTile.badgeLabel = total > 0 ? String(total) : nil
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
        // Prefer a broker that uses the secret without disclosing it
        // (docs/adr/0005-agent-trust-and-secret-use.md).
        let useWithoutReading: String
        switch entry.kind {
        case "core.ssh_key":
            useWithoutReading = "Use it without reading the key: "
                + "`keylease ssh <user@host> <command>`, or "
                + "`GIT_SSH_COMMAND=\"keylease ssh\" git ...`.\n"
        case "core.database":
            useWithoutReading = "Connect without reading the password: "
                + "`keylease db psql \(entry.id) -- -c '<sql>'` or "
                + "`keylease db exec \(entry.id) -- <command>`.\n"
        default:
            useWithoutReading = "If a program needs a secret in its environment, run it "
                + "with `keylease run --env NAME=\(entry.id)/<field> -- <command>` "
                + "instead of revealing the value.\n"
        }
        let readInstructions = entry.isAgentContent
            ? "Read its content: `keylease content get \(entry.id) --raw`\n"
                + "If access is denied, ask me to grant this agent read access."
            : useWithoutReading
                + "Inspect it: `keylease entries get \(entry.id)`\n"
                + "List its fields: `keylease entries view \(entry.id)`\n"
                + "Reveal only a needed field: `keylease entries reveal "
                + "\(entry.id) --field <field-id>`\n"
                + "Get its OTP if needed: `keylease entries totp \(entry.id)`"
        return """
            Use KeyLease Vault item \(quoted) (`\(entry.id)`) for this task.

            Connect to KeyLease directly; do not ask me to paste the item content.
            \(readInstructions)

            Keep returned content and secrets private. If the vault is locked, \
            ask me to unlock KeyLease. If a command reports approval_required, \
            rerun it with --wait-approval 120 and I will approve it in KeyLease.
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
        if phase != .ready {
            idleWatchTask?.cancel()
            stopApprovalWatch()
        }
        self.phase = phase
        self.message = message
    }

    // MARK: - Idle auto-lock

    /// True while an edit/create form holds an unsaved draft — locking
    /// out from under it would discard the draft; the editor recovers
    /// through its own unlock sheet instead.
    private var draftIsOpen: Bool {
        vault.workspaceMode == .edit || vault.workspaceMode == .create
    }

    /// An authorized RPC was rejected `vault_locked` (idle timeout, an
    /// external `lock`, a restarted daemon). An open editor is left
    /// alone; anywhere else the app refreshes into the lock screen.
    func handleSessionLocked() {
        guard phase == .ready, sessionLockCheck == nil, !draftIsOpen
        else { return }
        sessionLockCheck = Task { [weak self] in
            await self?.refresh()
            self?.sessionLockCheck = nil
        }
    }

    /// Arms a one-shot check for the moment the daemon's idle timeout
    /// should expire — `status` reports `idle_expires_at`, so no polling
    /// is needed. Activity re-arms the watch through `checkIdleLock`.
    private func scheduleIdleWatch(_ status: VaultStatus) {
        idleWatchTask?.cancel()
        idleWatchTask = nil
        guard !status.locked,
            let raw = status.idleExpiresAt,
            let expiry = Self.idleExpiryFormatter.date(from: raw)
                ?? ISO8601DateFormatter().date(from: raw)
        else { return }
        idleWatchTask = Task { [weak self] in
            let delay = expiry.timeIntervalSinceNow
            if delay > 0 {
                try? await Task.sleep(for: .seconds(delay))
            }
            guard !Task.isCancelled else { return }
            await self?.checkIdleLock()
        }
    }

    /// `idle_expires_at` is RFC 3339 — chrono emits fractional seconds.
    private static let idleExpiryFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [
            .withInternetDateTime, .withFractionalSeconds,
        ]
        return formatter
    }()

    /// Probes `status` at the reported expiry. Activity since the last
    /// refresh pushes the real expiry out — then the watch re-arms. A
    /// genuinely expired session drops to the lock screen unless an
    /// editor is holding a draft.
    private func checkIdleLock() async {
        guard phase == .ready else { return }
        let next: VaultStatus
        do {
            next = VaultStatus(try await client.unauthenticated(.status))
        } catch {
            // Transient transport failure — keep watching instead of
            // silently losing the auto-lock check.
            idleWatchTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled else { return }
                await self?.checkIdleLock()
            }
            return
        }
        status = next
        if next.locked {
            if draftIsOpen {
                // The editor keeps its draft and recovers through the
                // unlock sheet on save — but keep probing so the app
                // still locks once the user leaves the editor.
                idleWatchTask = Task { [weak self] in
                    try? await Task.sleep(for: .seconds(30))
                    guard !Task.isCancelled else { return }
                    await self?.checkIdleLock()
                }
                return
            }
            await refresh()
        } else {
            scheduleIdleWatch(next)
        }
    }
}
