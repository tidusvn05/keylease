import SwiftUI

import KeyLeaseCore

/// The Server section: this vault's link to keylease-server, the KeyLease
/// Console, console approvals (ADR 0011) and organization membership
/// (ADR 0012). Linking itself stays in the CLI (`keylease cloud init` /
/// `join`) because it prints a recovery kit once.
struct ServerView: View {
    let app: AppController
    @State private var joining = false
    @State private var shareAudit = true

    private var controller: ServerController { app.server }

    var body: some View {
        SectionScaffold(
            title: "Server",
            subtitle: "This vault's KeyLease server, console and organization",
            centered: controller.overview?.linked != true)
        {
            Button {
                Task { await controller.load() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .help("Refresh")
            .disabled(controller.loading)
        } content: {
            banners
            if let overview = controller.overview {
                if overview.linked {
                    linkCard(overview)
                    approvalsCard(overview)
                    organizationCard(overview)
                } else {
                    notLinked
                }
            } else if controller.loading {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .sheet(isPresented: $joining) {
            JoinOrganizationSheet(controller: controller)
        }
    }

    @ViewBuilder private var banners: some View {
        if let error = controller.error {
            MessageBanner(
                message: error, onDismiss: { controller.error = nil })
        }
        if let notice = controller.notice {
            MessageBanner(
                message: notice, tone: .info,
                onDismiss: { controller.notice = nil })
        }
    }

    private var notLinked: some View {
        ContentUnavailableView {
            Label("Not linked to a server", systemImage: "cloud")
        } description: {
            Text(
                "Link this vault once in Terminal. On your first device run "
                    + "`keylease cloud init --url https://keys.example.com "
                    + "--admin-token-file token`; on a VPS run "
                    + "`keylease cloud join --url …` with an invite code. "
                    + "It prints a recovery kit, so it is not done here."
            )
            .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Link

    private func linkCard(_ overview: CloudOverview) -> some View {
        KLCard {
            VStack(alignment: .leading, spacing: KL.Space.xs) {
                HStack {
                    Image(systemName: "cloud")
                    Text(overview.url ?? "Server")
                        .font(.callout.weight(.semibold))
                        .textSelection(.enabled)
                    Spacer()
                    if overview.isOwner {
                        KLButton(
                            title: controller.busy == .signIn
                                ? "Opening…" : "Open KeyLease Console",
                            icon: "safari", role: .primary
                        ) {
                            Task { await openConsole() }
                        }
                        .disabled(controller.busy != nil)
                    }
                }
                DetailRow(label: "Role", value: roleTitle(overview.role))
                DetailRow(label: "Device name", value: overview.name ?? "")
                DetailRow(label: "Fingerprint", value: overview.fingerprint ?? "")
                DetailRow(
                    label: "Last sync",
                    value: overview.lastSyncAt.map {
                        friendlyTime(ISO8601DateFormatter.parse($0))
                    } ?? "Not yet")
                if let lastError = overview.lastError, !lastError.isEmpty {
                    DetailRow(label: "Last error", value: lastError)
                }
                if overview.isOwner {
                    DetailRow(
                        label: "Nodes",
                        value: "\(overview.nodes) · \(overview.activeShares) "
                            + "active shares · \(overview.pendingRequests) "
                            + "pending requests")
                }
            }
        }
    }

    private func roleTitle(_ role: String?) -> String {
        switch role {
        case "owner": "Owner device"
        case "device": "Another device of the owner"
        case "node": "Node"
        default: role ?? ""
        }
    }

    private func openConsole() async {
        guard let link = await controller.consoleSignInLink() else { return }
        if !app.security.openExternal(link.url) {
            controller.error = UserMessage(
                title: "Could not open the browser",
                detail: "The server returned an unexpected console address.")
        }
    }

    // MARK: - Console approvals

    private func approvalsCard(_ overview: CloudOverview) -> some View {
        let approvals = overview.consoleApprovals
        return KLCard {
            VStack(alignment: .leading, spacing: KL.Space.m) {
                HStack {
                    Image(systemName: "person.badge.key")
                    Text("Approve from the KeyLease Console")
                        .font(.callout.weight(.semibold))
                    Spacer()
                    Text(approvals.enabled ? "On" : "Off")
                        .font(.callout)
                        .foregroundStyle(
                            approvals.enabled
                                ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                }
                Text(
                    "Requests from agents on this Mac also appear in the "
                        + "console, where you approve them with a passkey. "
                        + "The server only carries the decision: this Mac "
                        + "checks the passkey signature itself."
                )
                .font(.caption).foregroundStyle(.secondary)
                if approvals.enabled {
                    DetailRow(label: "Signed at", value: approvals.origin ?? "")
                    DetailRow(
                        label: "Passkeys",
                        value: approvals.passkeys.joined(separator: ", "))
                    DetailRow(
                        label: "Audit to console",
                        value: approvals.shareAudit ? "Uploaded" : "Not uploaded")
                    HStack {
                        KLButton(
                            title: controller.busy == .enableApprovals
                                ? "Updating…" : "Update passkeys"
                        ) {
                            Task {
                                await controller.enableConsoleApprovals(
                                    shareAudit: approvals.shareAudit)
                            }
                        }
                        .help("Run this after adding a passkey in the console")
                        KLButton(
                            title: controller.busy == .disableApprovals
                                ? "Turning off…" : "Turn off",
                            role: .destructive
                        ) {
                            Task { await controller.disableConsoleApprovals() }
                        }
                    }
                    .disabled(controller.busy != nil)
                } else {
                    Toggle(
                        "Also upload this vault's audit so the console lists it",
                        isOn: $shareAudit)
                    HStack {
                        KLButton(
                            title: controller.busy == .enableApprovals
                                ? "Turning on…" : "Turn on",
                            role: .primary
                        ) {
                            Task {
                                await controller.enableConsoleApprovals(
                                    shareAudit: shareAudit)
                            }
                        }
                        .disabled(controller.busy != nil)
                        Text("Register a passkey in the console first.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    // MARK: - Organization

    private func organizationCard(_ overview: CloudOverview) -> some View {
        KLCard {
            VStack(alignment: .leading, spacing: KL.Space.m) {
                HStack {
                    Image(systemName: "building.2")
                    Text("Organization").font(.callout.weight(.semibold))
                    Spacer()
                }
                if let org = overview.org {
                    Text(
                        "This vault is a managed node. The organization's "
                            + "signed rules can deny actions or require "
                            + "approval here; they never allow more."
                    )
                    .font(.caption).foregroundStyle(.secondary)
                    DetailRow(label: "Name", value: org.orgName)
                    DetailRow(label: "Organization id", value: org.orgId)
                    DetailRow(
                        label: "Policy version",
                        value: org.policyVersion.map(String.init)
                            ?? "None published yet")
                    DetailRow(
                        label: "Joined",
                        value: friendlyTime(ISO8601DateFormatter.parse(org.joinedAt)))
                    DetailRow(label: "Server key", value: org.keyId)
                    KLButton(
                        title: controller.busy == .leave ? "Leaving…" : "Leave",
                        role: .destructive
                    ) {
                        guard
                            confirmAction(
                                title: "Leave \(org.orgName)?",
                                message: "Its rules stop applying to this "
                                    + "vault. The organization sees that "
                                    + "this node stopped reporting.",
                                confirmLabel: "Leave", destructive: true)
                        else { return }
                        Task { await controller.leave() }
                    }
                    .disabled(controller.busy != nil)
                } else {
                    Text(
                        "Join with an enrollment code from your "
                            + "organization's console (Organization → "
                            + "Managed nodes). Its rules then apply to this "
                            + "vault."
                    )
                    .font(.caption).foregroundStyle(.secondary)
                    KLButton(title: "Join an organization…") { joining = true }
                        .disabled(controller.busy != nil)
                }
            }
        }
    }
}

private struct JoinOrganizationSheet: View {
    let controller: ServerController
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Join an organization").font(.headline)
            Text(
                "Paste the one-time enrollment code (it starts with "
                    + "`klnode_`). The organization can then deny actions "
                    + "or require approval on this vault."
            )
            .font(.callout).foregroundStyle(.secondary)
            if let error = controller.error {
                MessageBanner(
                    message: error, onDismiss: { controller.error = nil })
            }
            SecureField("klnode_…", text: $code)
                .textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                KLButton(title: "Cancel", role: .ghost) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                KLButton(
                    title: controller.busy == .join ? "Joining…" : "Join",
                    role: .primary
                ) {
                    Task {
                        if await controller.join(code: code) {
                            dismiss()
                        }
                    }
                }
                .disabled(
                    code.trimmingCharacters(in: .whitespaces).isEmpty
                        || controller.busy != nil)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(KL.Space.xxxl)
        .frame(width: 460)
    }
}
