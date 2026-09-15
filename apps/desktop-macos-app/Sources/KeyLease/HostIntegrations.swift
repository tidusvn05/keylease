import AppKit
import Foundation
import Vision

#if canImport(ScreenCaptureKit)
    import ScreenCaptureKit
#endif

/// macOS host capabilities the Flutter app reaches through method channels:
/// file pickers, `~/.ssh` key discovery, and TOTP QR capture.
@MainActor
final class HostIntegrations {
    // MARK: - File pickers (`pick_token_file` / `pick_ssh_key` / …)

    /// `NSOpenPanel` for the token file, SSH keys, and import sources.
    func pickFile(
        title: String,
        message: String,
        allowsDirectories: Bool = false,
        directory: URL? = nil
    ) -> URL? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.message = message
        panel.canChooseFiles = true
        panel.canChooseDirectories = allowsDirectories
        panel.allowsMultipleSelection = false
        if let directory { panel.directoryURL = directory }
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    // MARK: - SSH key discovery (`list_ssh_private_keys`)

    /// Scans `~/.ssh` for private keys by header sniffing — a file counts
    /// when it starts with a `-----BEGIN … PRIVATE KEY-----` banner and is
    /// not a `.pub` sidecar. Mirrors `discoverSshPrivateKeys` in the runner.
    func discoverSshPrivateKeys() -> [String] {
        let sshDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh")
        guard let names = try? FileManager.default.contentsOfDirectory(
            atPath: sshDir.path)
        else { return [] }
        return names
            .filter { !$0.hasSuffix(".pub") && !$0.hasPrefix(".") }
            .compactMap { name in
                let path = sshDir.appendingPathComponent(name)
                guard let head = try? Data(contentsOf: path)
                    .prefix(128),
                    String(decoding: head, as: UTF8.self)
                        .contains("PRIVATE KEY-----")
                else { return nil }
                return path.path
            }
            .sorted()
    }

    // MARK: - TOTP QR (`scan_totp_qr`)

    /// Vision barcode detection on a picked image file → `otpauth://` URI.
    func scanTotpQrFromImage(_ url: URL) -> String? {
        guard let image = NSImage(contentsOf: url)?.cgImage(
            forProposedRect: nil, context: nil, hints: nil)
        else { return nil }
        return firstOtpAuthUri(in: image)
    }

    private func firstOtpAuthUri(in image: CGImage) -> String? {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        let handler = VNImageRequestHandler(cgImage: image)
        try? handler.perform([request])
        return (request.results ?? [])
            .compactMap(\.payloadStringValue)
            .first { $0.hasPrefix("otpauth://") }
    }

    /// Screen-capture QR flow. `SCScreenshotManager` (macOS 15.4+) takes a
    /// user-guided screenshot; the capture lands on a file we feed to
    /// Vision. Returns `nil` when the user cancels or permission is missing;
    /// `outcome` tells the caller when to deep-link Screen Recording
    /// settings.
    #if canImport(ScreenCaptureKit)
        func captureScreenTotp() async -> (uri: String?, needsPermission: Bool)
        {
            if #available(macOS 15.4, *) {
                do {
                    let image = try await SCScreenshotManager.captureImage()
                    if let uri = firstOtpAuthUri(in: image) {
                        return (uri, false)
                    }
                    return (nil, false)
                } catch {
                    return (nil, true)
                }
            }
            return (nil, true)
        }
    #endif

    /// Deep-link to the Screen Recording pane so the user can grant the
    /// capture permission — `open_screen_recording_settings` in Flutter.
    func openScreenRecordingSettings() {
        NSWorkspace.shared.open(URL(
            string: "x-apple.systempreferences:"
                + "com.apple.preference.security?Privacy_ScreenCapture")!)
    }
}
