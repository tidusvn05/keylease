import AppKit
import Foundation
import LocalAuthentication
import UserNotifications

import KeyLeaseCore

/// Posts one system notification per new approval request — local or from a
/// paired remote vault — and routes a click back to the matching section.
///
/// Notifications carry the agent and the kind of action only, never the
/// item or field: they can appear on the lock screen.
@MainActor
final class ApprovalNotifier: NSObject, UNUserNotificationCenterDelegate {
    /// Called with the remote profile name, or nil for the local vault.
    var onOpen: (@MainActor (String?) -> Void)?
    private var notified = Set<String>()

    /// `UNUserNotificationCenter.current()` traps in a binary that is not
    /// inside an app bundle (`swift run`), so notifications are skipped
    /// there.
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleURL.pathExtension == "app"
            ? UNUserNotificationCenter.current() : nil
    }

    func install() {
        guard let center else { return }
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    /// Notifies about approvals not seen before. `source` is the remote
    /// profile name; nil means this Mac's vault.
    func notify(_ approvals: [ApprovalRecord], source: String?) {
        let fresh = approvals.filter {
            $0.decidableNow && !notified.contains(key($0.id, source))
        }
        for approval in fresh {
            notified.insert(key(approval.id, source))
        }
        guard let center, !fresh.isEmpty else { return }
        for approval in fresh {
            let content = UNMutableNotificationContent()
            let agent = approval.agentId.map(agentDisplayName) ?? "An agent"
            content.title =
                source.map { "Approval needed on \($0)" } ?? "Approval needed"
            content.body =
                "\(agent): \(approvalActionTitle(approval.action))"
                + (approval.risk.map { " · \($0.rawValue.uppercased())" } ?? "")
            content.sound = .default
            content.threadIdentifier = source ?? "local"
            if let source { content.userInfo = ["remote": source] }
            center.add(
                UNNotificationRequest(
                    identifier: key(approval.id, source), content: content,
                    trigger: nil))
        }
    }

    /// Withdraws notifications for requests that are no longer pending.
    func retire(keeping approvals: [ApprovalRecord], source: String?) {
        let live = Set(approvals.filter(\.decidableNow).map { key($0.id, source) })
        let prefix = (source ?? "local") + "/"
        let gone = notified.filter { $0.hasPrefix(prefix) && !live.contains($0) }
        guard !gone.isEmpty else { return }
        notified.subtract(gone)
        center?.removeDeliveredNotifications(withIdentifiers: Array(gone))
    }

    private func key(_ id: String, _ source: String?) -> String {
        (source ?? "local") + "/" + id
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let source = response.notification.request.content
            .userInfo["remote"] as? String
        await MainActor.run {
            NSApp.activate()
            onOpen?(source)
        }
    }
}

/// `agent_codex` → `codex`; the desktop owner reads as "KeyLease".
func agentDisplayName(_ agentId: String) -> String {
    if agentId == ConnectionDefaults.agentId { return "KeyLease" }
    return agentId.hasPrefix("agent_")
        ? String(agentId.dropFirst("agent_".count)) : agentId
}

/// Touch ID (or the login password) before a decision that outlives the
/// moment: a trust window, a high-risk approval, or a remote approval.
enum UserPresence {
    static func confirm(_ reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard
            context.canEvaluatePolicy(
                .deviceOwnerAuthentication, error: &error)
        else { return false }
        return (try? await context.evaluatePolicy(
            .deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }

    /// Whether approving `approval` with `duration` needs `confirm` first.
    static func required(
        for approval: ApprovalRecord, duration: TrustDuration
    ) -> Bool {
        duration != .once || approval.risk == .r3 || approval.risk == .r4
    }
}
