import AppKit
import Foundation
import Vision

#if canImport(ScreenCaptureKit)
    import ScreenCaptureKit
#endif

enum TotpScanResult: Equatable, Sendable {
    case found(String)
    case noCodeFound
    case permissionRequired
    case cancelled
    case failed(String)

    var hint: String? {
        switch self {
        case .found: "TOTP QR code found."
        case .noCodeFound:
            "No TOTP QR code found. Make the QR code visible or choose an image."
        case .permissionRequired:
            "Allow KeyLease in Screen Recording. If you just enabled it, quit and reopen KeyLease, then try again."
        case .cancelled: nil
        case .failed(let message): message
        }
    }
}

/// macOS file pickers, SSH key discovery, and local TOTP QR capture.
@MainActor
final class HostIntegrations {
    private let screenCaptureAccess: () -> Bool
    private let requestScreenCaptureAccess: () -> Bool
    private let screenScan: () async throws -> TotpScanResult

    init(
        screenCaptureAccess: @escaping () -> Bool = { CGPreflightScreenCaptureAccess() },
        requestScreenCaptureAccess: @escaping () -> Bool = { CGRequestScreenCaptureAccess() },
        screenScan: (() async throws -> TotpScanResult)? = nil
    ) {
        self.screenCaptureAccess = screenCaptureAccess
        self.requestScreenCaptureAccess = requestScreenCaptureAccess
        self.screenScan = screenScan ?? { try await Self.scanDisplays() }
    }

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

    func scanTotpQrFromImage(_ url: URL) -> TotpScanResult {
        guard let image = NSImage(contentsOf: url)?.cgImage(
            forProposedRect: nil, context: nil, hints: nil)
        else { return .failed("Could not read this image. Choose another image.") }
        return Self.scanTotpQr(in: image)
    }

    nonisolated static func scanTotpQr(in image: CGImage) -> TotpScanResult {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        do {
            try VNImageRequestHandler(cgImage: image).perform([request])
        } catch {
            return .failed("Could not read QR codes. Try again or choose another image.")
        }
        for payload in (request.results ?? []).compactMap(\.payloadStringValue) {
            let uri = payload.trimmingCharacters(in: .whitespacesAndNewlines)
            if let components = URLComponents(string: uri),
                components.scheme?.lowercased() == "otpauth",
                components.host?.lowercased() == "totp"
            {
                return .found(uri)
            }
        }
        return .noCodeFound
    }

    func captureScreenTotp() async -> TotpScanResult {
        guard screenCaptureAccess() || requestScreenCaptureAccess() else {
            return .permissionRequired
        }
        do {
            try Task.checkCancellation()
            return try await screenScan()
        } catch is CancellationError {
            return .cancelled
        } catch {
            let error = error as NSError
            if error.domain == SCStreamErrorDomain,
                error.code == SCStreamError.Code.userDeclined.rawValue
            {
                return .permissionRequired
            }
            return .failed("Could not capture the screen. Try again or choose an image.")
        }
    }

    /// Capture each display independently at its pixel scale, without KeyLease
    /// windows covering the QR. Pixels stay in memory and are never saved.
    private nonisolated static func scanDisplays() async throws -> TotpScanResult {
        let content = try await SCShareableContent.excludingDesktopWindows(
            false, onScreenWindowsOnly: true)
        let ownApplications = content.applications.filter {
            $0.processID == ProcessInfo.processInfo.processIdentifier
        }
        let mainDisplay = CGMainDisplayID()
        let displays = content.displays.sorted {
            if $0.displayID == mainDisplay { return $1.displayID != mainDisplay }
            if $1.displayID == mainDisplay { return false }
            return $0.displayID < $1.displayID
        }
        guard !displays.isEmpty else {
            return .failed("No screen is available. Choose a QR code image instead.")
        }
        var captureError: Error?
        var decodeFailure: TotpScanResult?
        for display in displays {
            try Task.checkCancellation()
            let filter = SCContentFilter(
                display: display, excludingApplications: ownApplications,
                exceptingWindows: [])
            let configuration = SCStreamConfiguration()
            configuration.width = max(1, Int((filter.contentRect.width
                * CGFloat(filter.pointPixelScale)).rounded()))
            configuration.height = max(1, Int((filter.contentRect.height
                * CGFloat(filter.pointPixelScale)).rounded()))
            configuration.showsCursor = false
            configuration.capturesAudio = false
            do {
                let image = try await SCScreenshotManager.captureImage(
                    contentFilter: filter, configuration: configuration)
                let result = scanTotpQr(in: image)
                if case .found = result { return result }
                if case .failed = result { decodeFailure = result }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                captureError = captureError ?? error
            }
        }
        if let captureError { throw captureError }
        return decodeFailure ?? .noCodeFound
    }

    /// Deep-link to the Screen Recording pane so the user can grant the
    /// capture permission — `open_screen_recording_settings` in Flutter.
    func openScreenRecordingSettings() {
        NSWorkspace.shared.open(URL(
            string: "x-apple.systempreferences:"
                + "com.apple.preference.security?Privacy_ScreenCapture")!)
    }
}
