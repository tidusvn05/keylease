import AppKit
import Foundation

/// Clipboard, lock-signal and external-URL handling — a direct port of the
/// `com.keylease/security` channel in the Flutter runner's
/// `MainFlutterWindow.swift`.
@MainActor
final class SecurityService {
    private var sensitivePasteboardChangeCount: Int?
    private var observerTokens: [NSObjectProtocol] = []

    /// Copies a secret and clears it after `seconds` only if the user has not
    /// overwritten the clipboard in the meantime — the same semantics the
    /// Flutter app exposes as `copySensitive`.
    func copySensitive(_ value: String, clearAfter seconds: Int = 30) {
        guard !value.isEmpty, value.utf8.count <= 1024 * 1024,
            (5...120).contains(seconds)
        else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(value, forType: .string) else { return }
        sensitivePasteboardChangeCount = pasteboard.changeCount
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            self?.clearSensitiveClipboardIfUnchanged()
        }
    }

    func clearSensitiveClipboardIfUnchanged() {
        let pasteboard = NSPasteboard.general
        guard sensitivePasteboardChangeCount == pasteboard.changeCount else {
            sensitivePasteboardChangeCount = nil
            return
        }
        pasteboard.clearContents()
        sensitivePasteboardChangeCount = nil
    }

    /// Sleep and screen-lock both wipe pending clipboard secrets and ask the
    /// caller to lock the vault — the `lockRequested` events in Flutter.
    /// Idempotent: WindowGroup `.task` can re-fire when a window reappears.
    func observeLockSignals(onLock: @escaping @MainActor () -> Void) {
        guard observerTokens.isEmpty else { return }
        let workspace = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.clearSensitiveClipboardIfUnchanged()
                onLock()
            }
        }
        observerTokens.append(workspace)
        let screen = DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.clearSensitiveClipboardIfUnchanged()
                onLock()
            }
        }
        observerTokens.append(screen)
    }

    /// `openExternalUrl`: only http(s) URLs with a host leave the app.
    @discardableResult
    func openExternal(_ raw: String) -> Bool {
        guard let url = URL(string: raw),
            ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
            url.host != nil
        else { return false }
        return NSWorkspace.shared.open(url)
    }

    /// `openGoogleAuthorization`: stricter — Google OAuth only.
    @discardableResult
    func openGoogleAuthorization(_ raw: String) -> Bool {
        guard let url = URL(string: raw),
            url.scheme == "https",
            url.host == "accounts.google.com"
        else { return false }
        return NSWorkspace.shared.open(url)
    }

    func stopObserving() {
        for token in observerTokens {
            NSWorkspace.shared.notificationCenter.removeObserver(token)
            DistributedNotificationCenter.default().removeObserver(token)
        }
        observerTokens = []
        clearSensitiveClipboardIfUnchanged()
    }

    deinit {
        MainActor.assumeIsolated {
            for token in observerTokens {
                NSWorkspace.shared.notificationCenter.removeObserver(token)
                DistributedNotificationCenter.default().removeObserver(token)
            }
        }
    }
}
