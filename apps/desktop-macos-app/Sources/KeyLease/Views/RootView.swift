import SwiftUI

/// Routes the single window on the phase machine — the equivalent of the
/// Dart app's phase switch in `keylease_app.dart`.
struct RootView: View {
    let app: AppController

    var body: some View {
        Group {
            switch app.phase {
            case .starting:
                ProgressView("Starting KeyLease…")
            case .onboarding:
                OnboardingView(app: app)
            case .provisioning:
                ProgressView("Setting up your vault…")
            case .repairRequired:
                RepairView(app: app)
            case .backgroundApprovalRequired:
                MessageView(
                    title: "Approve KeyLease in Login Items",
                    detail: app.message?.detail
                        ?? "macOS needs your approval before the KeyLease "
                        + "service can run in the background.",
                    actionLabel: "Open Login Items Settings"
                ) {
                    app.runtime.openLoginItemsSettings()
                } retry: {
                    Task { await app.bootstrap() }
                }
            case .serviceUnavailable:
                MessageView(
                    title: app.message?.title ?? "Service unavailable",
                    detail: app.message?.detail
                        ?? "The KeyLease service is not reachable.",
                    actionLabel: "Retry"
                ) {
                    Task { await app.bootstrap() }
                }
            case .locked:
                UnlockView(app: app)
            case .permissionDenied:
                MessageView(
                    title: "Access denied",
                    detail: app.message?.detail
                        ?? "This client is not allowed to use the vault.",
                    actionLabel: "Retry"
                ) {
                    Task { await app.refresh() }
                }
            case .ready:
                ContentView(app: app)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Shared "big message + optional action" layout for non-ready phases.
struct MessageView: View {
    let title: String
    let detail: String?
    let actionLabel: String?
    var action: (() -> Void)? = nil
    var retry: (() -> Void)? = nil

    var body: some View {
        KLStateScreen(icon: "lock.shield", title: title, detail: detail) {
            if actionLabel != nil || retry != nil {
                HStack(spacing: KL.Space.m) {
                    if let actionLabel, let action {
                        KLButton(
                            title: actionLabel, role: .primary,
                            prominent: true, action: action)
                    }
                    if let retry {
                        KLButton(title: "Retry", action: retry)
                    }
                }
            }
        }
    }
}
