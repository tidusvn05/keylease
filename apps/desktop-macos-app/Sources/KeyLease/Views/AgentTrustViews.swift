import AppKit
import SwiftUI
import SystemConfiguration

import KeyLeaseCore

// Approvals, agents and remote vaults (ADR 0005): approve once or trust an
// agent for a window capped by the request's risk tier, enroll agents with
// their own identity, and approve for paired headless vault nodes.

// MARK: - Approvals (`approvals_page.dart` + `RequestSummary`)

struct ApprovalsView: View {
    let app: AppController
    @State private var failure: UserMessage?
    @State private var deciding: DecisionTarget?

    private var controller: ApprovalsController { app.approvals }

    var body: some View {
        SectionScaffold(
            title: "Approvals",
            subtitle: "Requests waiting for a human decision",
            centered: controller.list.phase != .rows)
        {
            Button {
                Task { await controller.list.load() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .help("Refresh")
        } content: {
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            sectionBody(
                controller.list,
                emptyTitle: "Nothing waiting for you",
                emptyIcon: "checkmark.shield",
                emptyDetail: "New approval requests will appear here."
            ) { items in
                ForEach(items, id: \.id) { approval in
                    ApprovalCard(
                        approval: approval,
                        onApprove: {
                            deciding = DecisionTarget(
                                approval: approval, remote: nil)
                        },
                        onDeny: { await deny(approval) })
                }
            }
        }
        // Approvals arrive asynchronously — poll while the section is
        // open so a request is never silently stale. `.task` cancels
        // the loop when the view goes away.
        .task {
            while !Task.isCancelled {
                await controller.list.load()
                try? await Task.sleep(for: .seconds(30))
            }
        }
        .sheet(item: $deciding) { target in
            ApprovalDecisionSheet(target: target) { trust in
                try await controller.decide(
                    target.approval, approve: true, trust: trust)
            }
        }
    }

    private func deny(_ approval: ApprovalRecord) async {
        guard confirmDeny(approval) else { return }
        do {
            try await controller.decide(approval, approve: false)
        } catch let stale as StaleApprovalError {
            failure = UserMessage(
                title: "That request moved on", detail: stale.message)
        } catch {
            failure = UserMessage(error)
        }
    }
}

@MainActor
private func confirmDeny(_ approval: ApprovalRecord) -> Bool {
    let summary = approval.semanticSummary
    return confirmAction(
        title: "Deny this request?",
        message: "\(summary?.operation ?? approval.action ?? "Access")"
            + " on "
            + (summary?.target ?? approval.resource ?? "unknown resource"),
        confirmLabel: "Deny",
        destructive: true)
}

/// One pending request, local or on a remote node.
struct ApprovalCard: View {
    let approval: ApprovalRecord
    let onApprove: () -> Void
    let onDeny: () async -> Void
    @State private var busy = false

    private var expiresAt: Date? {
        ISO8601DateFormatter.parse(approval.expiresAt)
    }

    var body: some View {
        let summary = approval.semanticSummary
        let expired = (expiresAt ?? .distantPast) <= Date()
        return KLCard {
            VStack(alignment: .leading, spacing: KL.Space.xs) {
            HStack {
                Text(
                    summary?.operation ?? approvalActionTitle(approval.action))
                    .font(.callout.weight(.semibold))
                Spacer()
                if let risk = approval.risk {
                    RiskBadge(risk: risk)
                }
                if !approval.isPending || expired {
                    Text(expired ? "Expired" : approval.state.rawValue)
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(
                            Capsule().stroke(
                                Color.primary.opacity(0.2)))
                }
            }
            line("What it wants to do", approval.action ?? "unknown action")
            line(
                "Where",
                summary?.target ?? approval.resource ?? "unknown resource")
            line(
                "Requested by",
                approval.agentId.map(agentDisplayName) ?? "unknown client")
            if let purpose = approval.purpose, !purpose.isEmpty {
                // Declared by the agent; KeyLease does not verify it.
                line("Why (as the agent says)", purpose)
            }
            if let changed = summary?.changedFields, !changed.isEmpty {
                line("Fields it would change", changed.joined(separator: ", "))
            }
            if let blast = summary?.blastRadius {
                line("Scope", blast)
            }
            line(
                expired ? "Expired" : "Expires",
                "\(expiresAt.map(friendlyTime) ?? approval.expiresAt) · "
                    + "policy v\(approval.policyVersion)")
            SectionLabel(title: "Exact request").padding(.top, 4)
            Text(approval.requestDigestHex)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack {
                Spacer()
                KLButton(title: "Deny", role: .destructive) {
                    busy = true
                    Task {
                        await onDeny()
                        busy = false
                    }
                }
                .disabled(busy || !approval.decidableNow)
                KLButton(title: "Approve…", role: .primary) {
                    onApprove()
                }
                .disabled(busy || !approval.decidableNow)
            }
            .padding(.top, KL.Space.xs)
            }
        }
    }

    private func line(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Text("\(label):").foregroundStyle(.secondary)
            Text(value)
        }
        .font(.callout)
    }
}

private struct RiskBadge: View {
    let risk: RiskTier

    var body: some View {
        Text("\(risk.rawValue.uppercased()) risk")
            .font(.caption)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(
                Capsule().fill(
                    risk == .r3 || risk == .r4
                        ? KL.Colors.danger.opacity(0.14)
                        : KL.Colors.warning.opacity(0.14)))
    }
}

// MARK: - Decision sheet

/// The request being approved, and the node it lives on (nil: this Mac).
struct DecisionTarget: Identifiable {
    let approval: ApprovalRecord
    let remote: RemoteVault?

    var id: String { (remote?.name ?? "local") + "/" + approval.id }
}

/// Approve once, or trust the agent for a window. Only durations the
/// daemon would grant for this risk tier are offered (R4: once only).
struct ApprovalDecisionSheet: View {
    let target: DecisionTarget
    let onApprove: (TrustDecision?) async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var duration: TrustDuration = .once
    @State private var scope: TrustScope = .resource
    @State private var failure: UserMessage?
    @State private var busy = false

    private var approval: ApprovalRecord { target.approval }

    private var allowed: [TrustDuration] {
        TrustDuration.allowed(for: approval.risk)
    }

    private var agent: String {
        approval.agentId.map(agentDisplayName) ?? "this client"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(
                target.remote.map { "Approve on \($0.name)?" }
                    ?? "Approve this request?"
            )
            .font(.headline)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            KLInsetBlock {
                VStack(alignment: .leading, spacing: KL.Space.xs) {
                    Text(
                        "\(agent) wants to "
                            + approvalActionTitle(approval.action).lowercased()
                    )
                    .font(.callout.weight(.semibold))
                    Text(
                        approval.semanticSummary?.target ?? approval.resource
                            ?? "unknown resource"
                    )
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    if let purpose = approval.purpose, !purpose.isEmpty {
                        Text("“\(purpose)”")
                            .font(.callout).italic()
                            .foregroundStyle(.secondary)
                    }
                    if let risk = approval.risk {
                        RiskBadge(risk: risk)
                    }
                }
            }
            Picker("Allow", selection: $duration) {
                ForEach(allowed, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.menu)
            if allowed.count == 1 {
                Text(
                    approval.risk == .r4
                        ? "Revealing or injecting a secret is approved one "
                            + "request at a time."
                        : "This request can only be approved once."
                )
                .font(.caption).foregroundStyle(.secondary)
            }
            if duration != .once {
                Picker("Covers", selection: $scope) {
                    Text("This exact resource").tag(TrustScope.resource)
                    Text("Every field of this item").tag(TrustScope.item)
                }
                .pickerStyle(.radioGroup)
                Text(
                    "For \(duration.title), \(agent) can repeat this action "
                        + "without asking. Revoke it any time under "
                        + (target.remote == nil
                            ? "Agents." : "Remote Vaults.")
                )
                .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                KLButton(title: "Cancel", role: .ghost) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                KLButton(
                    title: busy
                        ? "Approving…"
                        : duration == .once ? "Approve once" : "Trust",
                    role: .primary)
                {
                    Task { await approve() }
                }
                .disabled(busy || !approval.decidableNow)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxl)
        .frame(width: 460)
    }

    private func approve() async {
        busy = true
        defer { busy = false }
        if target.remote != nil
            || UserPresence.required(for: approval, duration: duration)
        {
            let reason = duration == .once
                ? "approve a request from \(agent)"
                : "trust \(agent) for \(duration.title)"
            guard await UserPresence.confirm(reason) else {
                failure = UserMessage(
                    title: "Not approved",
                    detail: "Authentication was cancelled or is unavailable.")
                return
            }
        }
        do {
            try await onApprove(
                duration == .once
                    ? nil : TrustDecision(scope: scope, duration: duration))
            dismiss()
        } catch let stale as StaleApprovalError {
            failure = UserMessage(
                title: "That request moved on", detail: stale.message)
        } catch {
            failure = UserMessage(error)
        }
    }
}

// MARK: - Trusts

private struct TrustCard: View {
    let trust: TrustRecord
    let onRevoke: () async -> Void
    @State private var busy = false

    var body: some View {
        KLCard {
            VStack(alignment: .leading, spacing: KL.Space.xs) {
                HStack {
                    Text(
                        "\(agentDisplayName(trust.agentId)) · "
                            + trust.actionTitle
                    )
                    .font(.callout.weight(.semibold))
                    Spacer()
                    RiskBadge(risk: trust.risk)
                }
                Text(trust.resourcePrefix)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                HStack(spacing: 4) {
                    Text(
                        trust.scope == .item
                            ? "Every field of this item" : "This resource")
                    Text("·")
                    if let expires = trust.expiresDate {
                        Text("ends ") + Text(expires, style: .relative)
                    } else {
                        Text("ends \(trust.expiresAt)")
                    }
                }
                .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    KLButton(title: "Revoke", role: .destructive) {
                        guard
                            confirmAction(
                                title: "Revoke this trust?",
                                message: "\(agentDisplayName(trust.agentId)) "
                                    + "will need a new approval for "
                                    + trust.resourcePrefix + ".",
                                confirmLabel: "Revoke", destructive: true)
                        else { return }
                        busy = true
                        Task {
                            await onRevoke()
                            busy = false
                        }
                    }
                    .disabled(busy)
                }
            }
        }
    }
}

// MARK: - Agents

struct AgentsView: View {
    let app: AppController
    @State private var enrolling = false

    private var controller: TrustsController { app.trusts }

    var body: some View {
        SectionScaffold(
            title: "Agents",
            subtitle: "Agent identities and the trusts you have granted them")
        {
            HStack(spacing: KL.Space.m) {
                Button("Connect an agent") { enrolling = true }
                Button {
                    Task { await controller.list.load() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Refresh")
            }
        } content: {
            GuidanceCard(
                title: "Give each agent its own identity",
                summary: "An enrolled agent can search and read item "
                    + "metadata. Using a secret, signing in over SSH, "
                    + "connecting to a database or changing the vault waits "
                    + "for your approval here.",
                useWhen: "Never hand an agent ~/.keylease/desktop.token: "
                    + "that token is you, with no approvals.")
            if let error = controller.error {
                MessageBanner(
                    message: error, onDismiss: { controller.error = nil })
            }
            ForEach(controller.enrolled) { enrollment in
                EnrollmentCard(app: app, enrollment: enrollment)
            }
            SectionLabel(title: "Active trusts").padding(.top, KL.Space.m)
            sectionBody(
                controller.list,
                emptyTitle: "No active trusts",
                emptyIcon: "clock.badge.checkmark",
                emptyDetail: "Approve a request with a time window and it "
                    + "appears here until it ends or you revoke it."
            ) { items in
                ForEach(items) { trust in
                    TrustCard(trust: trust) {
                        await controller.revoke(trust)
                    }
                }
            }
        }
        .task { await controller.list.load() }
        .sheet(isPresented: $enrolling) {
            EnrollAgentSheet(app: app)
        }
    }
}

private struct EnrollmentCard: View {
    let app: AppController
    let enrollment: AgentEnrollment

    var body: some View {
        KLCard {
            VStack(alignment: .leading, spacing: KL.Space.m) {
                Text("\(agentDisplayName(enrollment.agentId)) is enrolled")
                    .font(.callout.weight(.semibold))
                Text(
                    "Set these in the agent's environment. The token stays "
                        + "in its file; the agent never needs to read it."
                )
                .font(.callout).foregroundStyle(.secondary)
                KLInsetBlock {
                    Text(enrollment.environment)
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                }
                HStack {
                    Spacer()
                    KLButton(title: "Copy", icon: "doc.on.doc") {
                        app.copySensitive(
                            enrollment.environment, clearAfter: 120,
                            label: "Environment")
                    }
                }
            }
        }
    }
}

private struct EnrollAgentSheet: View {
    let app: AppController
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var failure: UserMessage?
    @State private var busy = false

    private var trimmed: String {
        name.trimmingCharacters(in: .whitespaces)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connect an agent").font(.headline)
            Text(
                "Creates a client for one agent (Claude Code, Codex, a CI "
                    + "job…) with its own token file and approval rules."
            )
            .font(.callout).foregroundStyle(.secondary)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Agent name").font(.callout)
                TextField("codex", text: $name)
                    .textFieldStyle(.roundedBorder)
                Text("Letters, digits, '-' or '_'.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                KLButton(title: "Cancel", role: .ghost) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                KLButton(
                    title: busy ? "Connecting…" : "Connect", role: .primary)
                {
                    Task { await enroll() }
                }
                .disabled(!isValidAgentName(trimmed) || busy)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxl)
        .frame(width: 420)
    }

    private func enroll() async {
        busy = true
        defer { busy = false }
        do {
            _ = try await app.trusts.enroll(name: trimmed)
            dismiss()
        } catch {
            failure = UserMessage(error)
        }
    }
}

// MARK: - Remote vaults

struct RemoteVaultsView: View {
    let app: AppController
    @State private var pairing = false
    @State private var deciding: DecisionTarget?
    @State private var failure: UserMessage?

    private var controller: RemoteVaultsController { app.remotes }

    var body: some View {
        SectionScaffold(
            title: "Remote Vaults",
            subtitle: "Headless vault nodes this Mac approves for",
            centered: controller.vaults.isEmpty)
        {
            HStack(spacing: KL.Space.m) {
                Button("Pair a remote vault") { pairing = true }
                Button {
                    Task { await controller.refreshAll() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Refresh")
            }
        } content: {
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            if controller.vaults.isEmpty {
                ContentUnavailableView {
                    Label("No remote vaults", systemImage: "server.rack")
                } description: {
                    Text(
                        "On the server, run `keylease serve --approver-listen "
                            + "127.0.0.1:7443` behind HTTPS, then "
                            + "`keylease remote pairing-code`, and pair here."
                    )
                } actions: {
                    Button("Pair a remote vault") { pairing = true }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ForEach(controller.vaults) { vault in
                    remoteSection(vault)
                }
            }
        }
        .task { await controller.refreshAll() }
        .sheet(isPresented: $pairing) {
            PairRemoteSheet(app: app)
        }
        .sheet(item: $deciding) { target in
            ApprovalDecisionSheet(target: target) { trust in
                guard let vault = target.remote else { return }
                try await controller.decide(
                    target.approval, on: vault, approve: true, trust: trust)
            }
        }
    }

    @ViewBuilder private func remoteSection(_ vault: RemoteVault) -> some View {
        let state = controller.state(vault)
        KLCard {
            VStack(alignment: .leading, spacing: KL.Space.xs) {
                HStack {
                    Image(systemName: "server.rack")
                    Text(vault.name).font(.callout.weight(.semibold))
                    Spacer()
                    KLButton(title: "Forget", role: .ghost) {
                        guard
                            confirmAction(
                                title: "Forget \(vault.name)?",
                                message: "This Mac deletes its approver key. "
                                    + "Also run `keylease remote "
                                    + "revoke-device \(vault.deviceId)` on "
                                    + "the server.",
                                confirmLabel: "Forget", destructive: true)
                        else { return }
                        controller.remove(vault)
                    }
                }
                Text(vault.url)
                    .font(.callout.monospaced()).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Text(
                    "Device \(vault.deviceId) · key in "
                        + (vault.keySource == .keychain
                            ? "the Keychain" : "~/.keylease/remotes")
                )
                .font(.caption).foregroundStyle(.secondary)
            }
        }
        if let error = state.error {
            MessageBanner(
                message: error, actionLabel: "Retry",
                onAction: { Task { await controller.refresh(vault) } })
        }
        if state.loaded {
            if state.approvals.isEmpty {
                Text("No requests waiting on \(vault.name).")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(state.approvals, id: \.id) { approval in
                ApprovalCard(
                    approval: approval,
                    onApprove: {
                        deciding = DecisionTarget(
                            approval: approval, remote: vault)
                    },
                    onDeny: { await deny(approval, on: vault) })
            }
            if !state.trusts.isEmpty {
                SectionLabel(title: "Active trusts on \(vault.name)")
                    .padding(.top, KL.Space.s)
                ForEach(state.trusts) { trust in
                    TrustCard(trust: trust) {
                        await controller.revoke(trust, on: vault)
                    }
                }
            }
        }
    }

    private func deny(_ approval: ApprovalRecord, on vault: RemoteVault)
        async
    {
        guard confirmDeny(approval) else { return }
        do {
            try await controller.decide(
                approval, on: vault, approve: false, trust: nil)
        } catch let stale as StaleApprovalError {
            failure = UserMessage(
                title: "That request moved on", detail: stale.message)
        } catch {
            failure = UserMessage(error)
        }
    }
}

private struct PairRemoteSheet: View {
    let app: AppController
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = "https://"
    @State private var code = ""
    /// The Sharing name ("Alex's MacBook Pro"); `Host.current()` can block
    /// on DNS.
    @State private var deviceName =
        SCDynamicStoreCopyComputerName(nil, nil).map { $0 as String } ?? "Mac"
    @State private var failure: UserMessage?
    @State private var busy = false

    private var ready: Bool {
        RemoteApproverStore.isValidName(name)
            && (try? RemoteApproverStore.validatedURL(url)) != nil
            && !code.trimmingCharacters(in: .whitespaces).isEmpty
            && !deviceName.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pair a remote vault").font(.headline)
            Text(
                "On the server, `keylease remote pairing-code` prints a "
                    + "one-time code valid for 10 minutes. This Mac then "
                    + "approves that server's requests with a key kept in "
                    + "your Keychain."
            )
            .font(.callout).foregroundStyle(.secondary)
            if let failure {
                MessageBanner(
                    message: failure, onDismiss: { self.failure = nil })
            }
            labeled("Name on this Mac", TextField("vps", text: $name))
            labeled(
                "Approver URL",
                TextField("https://vault.example.com", text: $url))
            labeled("Pairing code", TextField("", text: $code))
            labeled(
                "Show this Mac on the server as",
                TextField("", text: $deviceName))
            HStack {
                Spacer()
                KLButton(title: "Cancel", role: .ghost) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                KLButton(title: busy ? "Pairing…" : "Pair", role: .primary) {
                    Task { await pair() }
                }
                .disabled(!ready || busy)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxl)
        .frame(width: 460)
    }

    private func labeled(_ label: String, _ field: TextField<Text>)
        -> some View
    {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            field.textFieldStyle(.roundedBorder)
        }
    }

    private func pair() async {
        busy = true
        defer { busy = false }
        do {
            try await app.remotes.pair(
                name: name,
                url: url,
                code: code,
                deviceName: deviceName.trimmingCharacters(in: .whitespaces))
            dismiss()
        } catch {
            failure = UserMessage(error)
        }
    }
}
