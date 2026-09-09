import Cocoa
import FlutterMacOS
import ScreenCaptureKit
import ServiceManagement
import UniformTypeIdentifiers
import Vision

private enum TotpQrScanner {
  static func payload(in image: CGImage) throws -> String? {
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    try VNImageRequestHandler(cgImage: image, options: [:]).perform([request])
    return (request.results ?? [])
      .compactMap { $0.payloadStringValue }
      .first { $0.lowercased().hasPrefix("otpauth://totp/") }
  }
}

private typealias LegacyScreenCaptureFunction = @convention(c) (
  CGRect, CGWindowListOption, CGWindowID, CGWindowImageOption
) -> Unmanaged<CGImage>?

@available(macOS 14.0, *)
private final class ScreenQrPickerCoordinator: NSObject, SCContentSharingPickerObserver {
  init(
    onSelection: @escaping (SCContentFilter) -> Void,
    onCancel: @escaping () -> Void,
    onFailure: @escaping (Error) -> Void
  ) {
    self.onSelection = onSelection
    self.onCancel = onCancel
    self.onFailure = onFailure
  }

  private let onSelection: (SCContentFilter) -> Void
  private let onCancel: () -> Void
  private let onFailure: (Error) -> Void
  private var finished = false

  func present() {
    let picker = SCContentSharingPicker.shared
    var configuration = SCContentSharingPickerConfiguration()
    configuration.allowedPickerModes = [.singleDisplay, .singleWindow]
    configuration.excludedBundleIDs = [Bundle.main.bundleIdentifier].compactMap { $0 }
    configuration.allowsChangingSelectedContent = false
    picker.defaultConfiguration = configuration
    picker.add(self)
    picker.isActive = true
    picker.present(using: .display)
  }

  private func finish(_ action: () -> Void) {
    guard !finished else { return }
    finished = true
    let picker = SCContentSharingPicker.shared
    picker.remove(self)
    picker.isActive = false
    action()
  }

  func contentSharingPicker(
    _ picker: SCContentSharingPicker,
    didCancelFor stream: SCStream?
  ) {
    finish(onCancel)
  }

  func contentSharingPicker(
    _ picker: SCContentSharingPicker,
    didUpdateWith filter: SCContentFilter,
    for stream: SCStream?
  ) {
    finish { onSelection(filter) }
  }

  func contentSharingPickerStartDidFailWithError(_ error: Error) {
    finish { onFailure(error) }
  }
}

class MainFlutterWindow: NSWindow {
  private var observerTokens: [NSObjectProtocol] = []
  private var securityScopedURLs: [URL] = []
  private var sensitivePasteboardChangeCount: Int?
  private var menuChannel: FlutterMethodChannel?
  private var runtimeBridge: AnyObject?
  private var settingsWindowController: KeyLeaseSettingsWindowController?
  private var screenScanWindowState: (alpha: CGFloat, ignoresMouseEvents: Bool)?
  private var screenQrPickerCoordinator: AnyObject?

  private func restoreAfterScreenScan(wasVisible: Bool) {
    if let state = screenScanWindowState {
      alphaValue = state.alpha
      ignoresMouseEvents = state.ignoresMouseEvents
      screenScanWindowState = nil
    }
    guard wasVisible else { return }
    makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  private func scanCapturedImages(
    _ images: [CGImage],
    wasVisible: Bool,
    result: @escaping FlutterResult
  ) {
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      do {
        var payload: String?
        for image in images where payload == nil {
          payload = try TotpQrScanner.payload(in: image)
        }
        DispatchQueue.main.async {
          self?.restoreAfterScreenScan(wasVisible: wasVisible)
          guard let payload else {
            result(FlutterError(
              code: "TOTP_QR_NOT_FOUND",
              message: "No TOTP QR code was found on the visible displays.",
              details: nil))
            return
          }
          result(payload)
        }
      } catch {
        DispatchQueue.main.async {
          self?.restoreAfterScreenScan(wasVisible: wasVisible)
          result(FlutterError(
            code: "QR_SCAN_FAILED",
            message: "The screen QR code could not be scanned.",
            details: String(describing: error)))
        }
      }
    }
  }

  /// macOS 14 added a one-shot in-memory screenshot API. Nothing is written
  /// to disk and KeyLease itself is excluded from every captured display.
  @available(macOS 14.0, *)
  private func captureVisibleDisplays(
    wasVisible: Bool,
    result: @escaping FlutterResult
  ) {
    SCShareableContent.getExcludingDesktopWindows(
      false,
      onScreenWindowsOnly: true
    ) { [weak self] content, error in
      guard let self else { return }
      guard let content else {
        DispatchQueue.main.async {
          self.restoreAfterScreenScan(wasVisible: wasVisible)
          result(FlutterError(
            code: "SCREEN_CAPTURE_FAILED",
            message: "The visible displays could not be read.",
            details: error.map(String.init(describing:))))
        }
        return
      }

      let bundleIdentifier = Bundle.main.bundleIdentifier
      let excludedApplications = content.applications.filter {
        $0.bundleIdentifier == bundleIdentifier
      }
      let group = DispatchGroup()
      let lock = NSLock()
      var images: [CGImage] = []
      var captureError: Error?

      for display in content.displays {
        let filter = SCContentFilter(
          display: display,
          excludingApplications: excludedApplications,
          exceptingWindows: [])
        let configuration = SCStreamConfiguration()
        configuration.width = display.width
        configuration.height = display.height
        configuration.showsCursor = false
        group.enter()
        SCScreenshotManager.captureImage(
          contentFilter: filter,
          configuration: configuration
        ) { image, error in
          lock.lock()
          if let image {
            images.append(image)
          } else if captureError == nil {
            captureError = error
          }
          lock.unlock()
          group.leave()
        }
      }

      group.notify(queue: .main) {
        if images.isEmpty {
          self.restoreAfterScreenScan(wasVisible: wasVisible)
          result(FlutterError(
            code: "SCREEN_CAPTURE_FAILED",
            message: "No visible display could be captured.",
            details: captureError.map(String.init(describing:))))
          return
        }
        self.scanCapturedImages(images, wasVisible: wasVisible, result: result)
      }
    }
  }

  @available(macOS 14.0, *)
  private func captureSelectedContent(
    _ filter: SCContentFilter,
    wasVisible: Bool,
    result: @escaping FlutterResult
  ) {
    let info = SCShareableContent.info(for: filter)
    let configuration = SCStreamConfiguration()
    configuration.width = max(1, Int(info.contentRect.width * CGFloat(info.pointPixelScale)))
    configuration.height = max(1, Int(info.contentRect.height * CGFloat(info.pointPixelScale)))
    configuration.showsCursor = false
    SCScreenshotManager.captureImage(
      contentFilter: filter,
      configuration: configuration
    ) { [weak self] image, error in
      DispatchQueue.main.async {
        guard let self else { return }
        guard let image else {
          self.restoreAfterScreenScan(wasVisible: wasVisible)
          result(FlutterError(
            code: "SCREEN_CAPTURE_FAILED",
            message: "The selected screen content could not be captured.",
            details: error.map(String.init(describing:))))
          return
        }
        self.scanCapturedImages([image], wasVisible: wasVisible, result: result)
      }
    }
  }

  private func prepareWindowForScreenScan() -> Bool {
    let wasVisible = isVisible
    screenScanWindowState = (alpha: alphaValue, ignoresMouseEvents: ignoresMouseEvents)
    // Keep the window ordered so AppKit does not automatically terminate the
    // application when its last visible window disappears. A transparent,
    // click-through window leaves the selected content unobstructed.
    ignoresMouseEvents = true
    alphaValue = 0
    return wasVisible
  }

  @available(macOS 14.0, *)
  private func presentScreenContentPicker(result: @escaping FlutterResult) {
    let coordinator = ScreenQrPickerCoordinator(
      onSelection: { [weak self] filter in
        guard let self else { return }
        self.screenQrPickerCoordinator = nil
        let wasVisible = self.prepareWindowForScreenScan()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
          self?.captureSelectedContent(filter, wasVisible: wasVisible, result: result)
        }
      },
      onCancel: { [weak self] in
        self?.screenQrPickerCoordinator = nil
        result(nil)
      },
      onFailure: { [weak self] error in
        self?.screenQrPickerCoordinator = nil
        result(FlutterError(
          code: "SCREEN_PICKER_FAILED",
          message: "The macOS screen picker could not be opened.",
          details: String(describing: error)))
      })
    screenQrPickerCoordinator = coordinator
    coordinator.present()
  }

  /// ScreenCaptureKit has no one-shot screenshot API on macOS 13. Resolve the
  /// system's legacy in-memory capture symbol only for that OS version; this
  /// keeps the supported deployment target without persisting a screenshot.
  private func captureVisibleDisplaysLegacy(
    wasVisible: Bool,
    result: @escaping FlutterResult
  ) {
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGWindowListCreateImage") else {
      restoreAfterScreenScan(wasVisible: wasVisible)
      result(FlutterError(
        code: "SCREEN_CAPTURE_FAILED",
        message: "Screen capture is unavailable on this macOS version.",
        details: nil))
      return
    }
    let capture = unsafeBitCast(symbol, to: LegacyScreenCaptureFunction.self)
    guard let image = capture(
      .infinite,
      .optionOnScreenOnly,
      kCGNullWindowID,
      [.bestResolution, .boundsIgnoreFraming]
    )?.takeRetainedValue() else {
      restoreAfterScreenScan(wasVisible: wasVisible)
      result(FlutterError(
        code: "SCREEN_CAPTURE_FAILED",
        message: "The visible displays could not be captured.",
        details: nil))
      return
    }
    scanCapturedImages([image], wasVisible: wasVisible, result: result)
  }

  private func scanTotpQrCodeFromScreen(result: @escaping FlutterResult) {
    guard screenScanWindowState == nil, screenQrPickerCoordinator == nil else {
      result(FlutterError(
        code: "SCREEN_SCAN_IN_PROGRESS",
        message: "A screen scan is already in progress.",
        details: nil))
      return
    }
    if !CGPreflightScreenCaptureAccess() {
      if #available(macOS 14.0, *) {
        // The Apple-provided picker grants access to only the content selected
        // for this scan. It also works for frequently rebuilt, ad-hoc signed
        // development apps whose persistent TCC identity changes each build.
        presentScreenContentPicker(result: result)
        return
      }
      guard CGRequestScreenCaptureAccess() else {
        result(FlutterError(
          code: "SCREEN_RECORDING_PERMISSION_REQUIRED",
          message: "Allow KeyLease in Privacy & Security > Screen Recording.",
          details: nil))
        return
      }
    }

    let wasVisible = prepareWindowForScreenScan()
    // Give WindowServer one frame to update the compositor before the shot.
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
      guard let self else { return }
      if #available(macOS 14.0, *) {
        self.captureVisibleDisplays(wasVisible: wasVisible, result: result)
      } else {
        self.captureVisibleDisplaysLegacy(wasVisible: wasVisible, result: result)
      }
    }
  }

  private func clearSensitiveClipboardIfUnchanged() {
    let pasteboard = NSPasteboard.general
    guard sensitivePasteboardChangeCount == pasteboard.changeCount else {
      sensitivePasteboardChangeCount = nil
      return
    }
    pasteboard.clearContents()
    sensitivePasteboardChangeCount = nil
  }

  /// Forwards a menu selection to Flutter, which owns the actual behaviour.
  @objc private func keyLeaseMenuAction(_ sender: NSMenuItem) {
    guard let action = sender.representedObject as? String else { return }
    menuChannel?.invokeMethod("menuAction", arguments: action)
  }

  /// Retargets the first menu item with the exact shortcut, depth first.
  @discardableResult
  private func retarget(
    _ menu: NSMenu,
    keyEquivalent: String,
    modifiers: NSEvent.ModifierFlags,
    action: String
  ) -> Bool {
    for item in menu.items {
      if item.keyEquivalent == keyEquivalent, item.keyEquivalentModifierMask == modifiers {
        item.target = self
        item.action = #selector(keyLeaseMenuAction(_:))
        item.representedObject = action
        return true
      }
      if let submenu = item.submenu,
        retarget(submenu, keyEquivalent: keyEquivalent, modifiers: modifiers, action: action)
      {
        return true
      }
    }
    return false
  }

  private func vaultMenuItem(_ title: String, _ key: String, _ action: String) -> NSMenuItem {
    let item = NSMenuItem(
      title: title, action: #selector(keyLeaseMenuAction(_:)), keyEquivalent: key)
    item.target = self
    item.representedObject = action
    return item
  }

  private func showSettingsWindow() {
    if settingsWindowController == nil {
      settingsWindowController = KeyLeaseSettingsWindowController()
    }
    settingsWindowController?.showWindow(nil)
    settingsWindowController?.window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  private func sshPrivateKeyCandidates() -> [[String: String]] {
    let directory = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".ssh", isDirectory: true)
    let excluded = Set(["config", "known_hosts", "known_hosts.old", "authorized_keys"])
    let urls = (try? FileManager.default.contentsOfDirectory(
      at: directory,
      includingPropertiesForKeys: [.isRegularFileKey, .isReadableKey],
      options: [.skipsHiddenFiles]
    )) ?? []
    let priority = ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]
    return urls.compactMap { url -> [String: String]? in
      let name = url.lastPathComponent
      guard !name.hasSuffix(".pub"), !excluded.contains(name), self.isSshPrivateKey(url) else {
        return nil
      }
      return ["path": url.path, "name": name]
    }.sorted { left, right in
      let leftRank = priority.firstIndex(of: left["name"] ?? "") ?? priority.count
      let rightRank = priority.firstIndex(of: right["name"] ?? "") ?? priority.count
      if leftRank != rightRank { return leftRank < rightRank }
      return (left["name"] ?? "").localizedStandardCompare(right["name"] ?? "") == .orderedAscending
    }
  }

  private func isSshPrivateKey(_ url: URL) -> Bool {
    let headers = [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----"
    ]
    guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isReadableKey]),
          values.isRegularFile == true,
          values.isReadable == true,
          let handle = try? FileHandle(forReadingFrom: url) else { return false }
    defer { try? handle.close() }
    let data = try? handle.read(upToCount: 256)
    guard let data,
          let prefix = String(data: data, encoding: .utf8) else { return false }
    return headers.contains(where: prefix.contains)
  }

  private func selectSshPrivateKey(result: @escaping FlutterResult) {
    let panel = NSOpenPanel()
    panel.title = "Choose an SSH private key"
    panel.message = "Only the local path is saved on this Mac. Key contents are never copied into the vault."
    panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".ssh", isDirectory: true)
    panel.canChooseDirectories = false
    panel.canChooseFiles = true
    panel.allowsMultipleSelection = false
    panel.beginSheetModal(for: self) { response in
      guard response == .OK, let url = panel.url else {
        result(nil)
        return
      }
      guard self.isSshPrivateKey(url) else {
        result(FlutterError(
          code: "SSH_PRIVATE_KEY_INVALID",
          message: "The selected file is not a recognized SSH private key.",
          details: nil))
        return
      }
      if url.startAccessingSecurityScopedResource() {
        self.securityScopedURLs.append(url)
      }
      result(url.path)
    }
  }

  /// Without this, the template menu swallows the shortcuts KeyLease uses:
  /// AppKit consumes a menu key equivalent before the Flutter view sees it,
  /// so Command-F and Command-Comma would never reach the app's shortcuts.
  private func wireMenu(channel: FlutterMethodChannel) {
    menuChannel = channel
    guard let mainMenu = NSApp.mainMenu else { return }
    retarget(mainMenu, keyEquivalent: "f", modifiers: [.command], action: "search")
    retarget(mainMenu, keyEquivalent: ",", modifiers: [.command], action: "settings")

    let vaultMenu = NSMenu(title: "Vault")
    vaultMenu.addItem(vaultMenuItem("New Item", "n", "new_item"))
    vaultMenu.addItem(vaultMenuItem("Refresh", "r", "refresh"))
    vaultMenu.addItem(.separator())
    vaultMenu.addItem(vaultMenuItem("Lock Vault", "l", "lock"))
    let vaultItem = NSMenuItem(title: "Vault", action: nil, keyEquivalent: "")
    vaultItem.submenu = vaultMenu
    // After the application and Edit menus, before Window and Help.
    mainMenu.insertItem(vaultItem, at: min(2, mainMenu.items.count))
  }

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    // Match modern macOS vault apps: content supplies a compact unified
    // toolbar while AppKit keeps ownership of traffic lights and resizing.
    self.titleVisibility = .hidden
    self.titlebarAppearsTransparent = true
    self.styleMask.insert(.fullSizeContentView)
    self.isMovableByWindowBackground = true
    // Restores the size and position the user left the window in.
    self.setFrameAutosaveName("KeyLeaseMainWindow")

    let registrar = flutterViewController.registrar(forPlugin: "KeyLeaseSecurity")
    let channel = FlutterMethodChannel(
      name: "com.keylease/security",
      binaryMessenger: registrar.messenger)
    channel.setMethodCallHandler { [weak self] call, result in
      guard let self else {
        result(FlutterError(code: "WINDOW_CLOSED", message: nil, details: nil))
        return
      }
      if call.method == "openSettingsWindow" {
        self.showSettingsWindow()
        result(true)
        return
      }
      if call.method == "openGoogleAuthorization" {
        guard
          let raw = call.arguments as? String,
          let url = URL(string: raw),
          url.scheme == "https",
          url.host == "accounts.google.com"
        else {
          result(FlutterError(code: "INVALID_GOOGLE_URL", message: nil, details: nil))
          return
        }
        result(NSWorkspace.shared.open(url))
        return
      }
      if call.method == "openExternalUrl" {
        guard
          let raw = call.arguments as? String,
          let url = URL(string: raw),
          ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
          url.host != nil
        else {
          result(FlutterError(code: "INVALID_EXTERNAL_URL", message: nil, details: nil))
          return
        }
        result(NSWorkspace.shared.open(url))
        return
      }
      if call.method == "copySensitive" {
        guard
          let arguments = call.arguments as? [String: Any],
          let value = arguments["value"] as? String,
          let seconds = arguments["clear_after_seconds"] as? Int,
          !value.isEmpty,
          value.utf8.count <= 1024 * 1024,
          (5...120).contains(seconds)
        else {
          result(FlutterError(code: "INVALID_CLIPBOARD_REQUEST", message: nil, details: nil))
          return
        }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(value, forType: .string) else {
          result(FlutterError(code: "CLIPBOARD_WRITE_FAILED", message: nil, details: nil))
          return
        }
        self.sensitivePasteboardChangeCount = pasteboard.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(seconds)) { [weak self] in
          self?.clearSensitiveClipboardIfUnchanged()
        }
        result(true)
        return
      }
      if call.method == "clearSensitiveClipboard" {
        self.clearSensitiveClipboardIfUnchanged()
        result(true)
        return
      }
      if call.method == "openScreenRecordingSettings" {
        guard let url = URL(
          string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
        ) else {
          result(false)
          return
        }
        result(NSWorkspace.shared.open(url))
        return
      }
      if call.method == "scanTotpQrCodeFromScreen" {
        self.scanTotpQrCodeFromScreen(result: result)
        return
      }
      if call.method == "scanTotpQrCode" {
        let panel = NSOpenPanel()
        panel.title = "Choose a TOTP QR code image"
        panel.message = "KeyLease reads the QR code locally. The image is not uploaded."
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.image]
        panel.beginSheetModal(for: self) { response in
          guard response == .OK, let url = panel.url else {
            result(nil)
            return
          }
          guard let image = NSImage(contentsOf: url),
                let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            result(FlutterError(code: "QR_IMAGE_INVALID", message: "The selected image could not be read.", details: nil))
            return
          }
          DispatchQueue.global(qos: .userInitiated).async {
            do {
              let payload = try TotpQrScanner.payload(in: cgImage)
              DispatchQueue.main.async {
                guard let payload else {
                  result(FlutterError(code: "TOTP_QR_NOT_FOUND", message: "No TOTP QR code was found in this image.", details: nil))
                  return
                }
                result(payload)
              }
            } catch {
              DispatchQueue.main.async {
                result(FlutterError(code: "QR_SCAN_FAILED", message: "The QR code could not be scanned.", details: String(describing: error)))
              }
            }
          }
        }
        return
      }
      if call.method == "discoverSshPrivateKeys" {
        result(self.sshPrivateKeyCandidates())
        return
      }
      if call.method == "selectSshPrivateKey" {
        self.selectSshPrivateKey(result: result)
        return
      }
      guard call.method == "selectClientToken" else {
        result(FlutterMethodNotImplemented)
        return
      }
      let panel = NSOpenPanel()
      panel.canChooseDirectories = false
      panel.canChooseFiles = true
      panel.allowsMultipleSelection = false
      panel.beginSheetModal(for: self) { response in
        guard response == .OK, let url = panel.url else {
          result(nil)
          return
        }
        if url.startAccessingSecurityScopedResource() {
          self.securityScopedURLs.append(url)
        }
        result(url.path)
      }
    }

    let workspaceToken = NSWorkspace.shared.notificationCenter.addObserver(
      forName: NSWorkspace.willSleepNotification,
      object: nil,
      queue: .main
    ) { [weak self] _ in
      self?.clearSensitiveClipboardIfUnchanged()
      channel.invokeMethod("lockRequested", arguments: "system_sleep")
    }
    observerTokens.append(workspaceToken)
    let screenToken = DistributedNotificationCenter.default().addObserver(
      forName: Notification.Name("com.apple.screenIsLocked"),
      object: nil,
      queue: .main
    ) { [weak self] _ in
      self?.clearSensitiveClipboardIfUnchanged()
      channel.invokeMethod("lockRequested", arguments: "screen_lock")
    }
    observerTokens.append(screenToken)

    wireMenu(channel: channel)

    let runtimeBridge = LocalRuntimeBridge(window: self, messenger: registrar.messenger)
    runtimeBridge.register()
    self.runtimeBridge = runtimeBridge

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }

  deinit {
    clearSensitiveClipboardIfUnchanged()
    for token in observerTokens {
      NSWorkspace.shared.notificationCenter.removeObserver(token)
      DistributedNotificationCenter.default().removeObserver(token)
    }
    for url in securityScopedURLs {
      url.stopAccessingSecurityScopedResource()
    }
  }
}

/// A real secondary macOS window backed by an independent Flutter engine.
/// Both engines connect to the same local KeyLease daemon; decrypted UI state
/// is never copied between windows.
private final class KeyLeaseSettingsWindowController: NSWindowController {
  private let engine: FlutterEngine
  private var runtimeBridge: AnyObject?
  private var securityChannel: FlutterMethodChannel?

  init() {
    let project = FlutterDartProject()
    engine = FlutterEngine(name: "KeyLeaseSettings", project: project)
    _ = engine.run(withEntrypoint: "settingsMain")

    let viewController = FlutterViewController(engine: engine, nibName: nil, bundle: nil)
    RegisterGeneratedPlugins(registry: viewController)
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 780, height: 620),
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered,
      defer: false
    )
    window.title = "KeyLease Settings"
    window.contentMinSize = NSSize(width: 680, height: 500)
    window.contentViewController = viewController
    window.isReleasedWhenClosed = false
    window.setFrameAutosaveName("KeyLeaseSettingsWindow")
    window.center()
    super.init(window: window)

    if #available(macOS 13.0, *) {
      let bridge = LocalRuntimeBridge(window: window, messenger: engine.binaryMessenger)
      bridge.register()
      runtimeBridge = bridge
    }

    let channel = FlutterMethodChannel(
      name: "com.keylease/security",
      binaryMessenger: engine.binaryMessenger
    )
    channel.setMethodCallHandler { [weak window] call, result in
      switch call.method {
      case "openGoogleAuthorization":
        guard let raw = call.arguments as? String,
              let url = URL(string: raw),
              url.scheme == "https",
              url.host == "accounts.google.com" else {
          return result(FlutterError(code: "INVALID_GOOGLE_URL", message: nil, details: nil))
        }
        result(NSWorkspace.shared.open(url))
      case "openExternalUrl":
        guard let raw = call.arguments as? String,
              let url = URL(string: raw),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil else {
          return result(FlutterError(code: "INVALID_EXTERNAL_URL", message: nil, details: nil))
        }
        result(NSWorkspace.shared.open(url))
      case "clearSensitiveClipboard":
        result(true)
      case "openSettingsWindow":
        window?.makeKeyAndOrderFront(nil)
        result(true)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    securityChannel = channel
  }

  required init?(coder: NSCoder) {
    fatalError("init(coder:) has not been implemented")
  }

  deinit {
    securityChannel?.setMethodCallHandler(nil)
    engine.shutDownEngine()
  }
}

@available(macOS 13.0, *)
private final class LocalRuntimeBridge {
  private weak var window: NSWindow?
  private let channel: FlutterMethodChannel
  private let service = SMAppService.agent(plistName: "app.keylease.service.plist")

  init(window: NSWindow, messenger: FlutterBinaryMessenger) {
    self.window = window
    channel = FlutterMethodChannel(name: "com.keylease/runtime", binaryMessenger: messenger)
  }

  func register() {
    channel.setMethodCallHandler { [weak self] call, result in
      guard let self else { return result(FlutterError(code: "WINDOW_CLOSED", message: nil, details: nil)) }
      switch call.method {
      case "inspect": self.run(arguments: ["desktop", "inspect"], input: nil, result: result)
      case "inspectSource":
        guard let values = call.arguments as? [String: Any], let path = values["path"] as? String else {
          return result(FlutterError(code: "INVALID_REQUEST", message: "Missing vault path", details: nil))
        }
        self.run(arguments: ["desktop", "inspect-source", path], input: nil, result: result)
      case "provision":
        guard let values = call.arguments as? [String: Any],
              let data = try? JSONSerialization.data(withJSONObject: values) else {
          return result(FlutterError(code: "INVALID_REQUEST", message: "Invalid setup request", details: nil))
        }
        self.run(arguments: ["desktop", "provision"], input: data, result: result, returnValue: false)
      case "listVaults":
        self.run(arguments: ["desktop", "vaults-list"], input: nil, result: result)
      case "createVault":
        guard let values = call.arguments as? [String: Any],
              let data = try? JSONSerialization.data(withJSONObject: values) else {
          return result(FlutterError(code: "INVALID_REQUEST", message: "Invalid vault request", details: nil))
        }
        self.run(arguments: ["desktop", "vault-create"], input: data, result: result, returnValue: false)
      case "switchVault":
        guard let values = call.arguments as? [String: Any], let id = values["id"] as? String else {
          return result(FlutterError(code: "INVALID_REQUEST", message: "Missing vault id", details: nil))
        }
        self.run(arguments: ["desktop", "vault-switch", id], input: nil, result: result, returnValue: false)
      case "renameVault":
        guard let values = call.arguments as? [String: Any],
              let id = values["id"] as? String, let name = values["name"] as? String else {
          return result(FlutterError(code: "INVALID_REQUEST", message: "Missing vault name", details: nil))
        }
        self.run(arguments: ["desktop", "vault-rename", id, name], input: nil, result: result, returnValue: false)
      case "ensureService": self.ensureService(restart: false, result: result)
      case "restartService": self.ensureService(restart: true, result: result)
      case "openLoginItemsSettings":
        SMAppService.openSystemSettingsLoginItems()
        result(nil)
      case "openDataFolder":
        let folder = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keylease")
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        result(NSWorkspace.shared.open(folder))
      case "chooseVaultSource": self.chooseVault(result: result)
      default: result(FlutterMethodNotImplemented)
      }
    }
  }

  private func helperURL() -> URL? {
    Bundle.main.resourceURL?.appendingPathComponent("keylease")
  }

  private func run(arguments: [String], input: Data?, result: @escaping FlutterResult, returnValue: Bool = true) {
    guard let executable = helperURL() else {
      return result(FlutterError(code: "HELPER_MISSING", message: "KeyLease runtime is missing", details: nil))
    }
    DispatchQueue.global(qos: .userInitiated).async {
      let process = Process()
      let output = Pipe()
      process.executableURL = executable
      process.arguments = arguments
      process.standardOutput = output
      process.standardError = FileHandle.nullDevice
      if let input {
        let pipe = Pipe()
        process.standardInput = pipe
        do {
          try process.run()
          pipe.fileHandleForWriting.write(input)
          try? pipe.fileHandleForWriting.close()
        } catch {
          return DispatchQueue.main.async { result(FlutterError(code: "HELPER_FAILED", message: "Could not start KeyLease", details: nil)) }
        }
      } else {
        do { try process.run() }
        catch { return DispatchQueue.main.async { result(FlutterError(code: "HELPER_FAILED", message: "Could not start KeyLease", details: nil)) } }
      }
      process.waitUntilExit()
      let data = output.fileHandleForReading.readDataToEndOfFile()
      guard process.terminationStatus == 0 else {
        return DispatchQueue.main.async { result(FlutterError(code: "HELPER_FAILED", message: "KeyLease could not complete setup", details: nil)) }
      }
      if !returnValue { return DispatchQueue.main.async { result(nil) } }
      guard let object = try? JSONSerialization.jsonObject(with: data) else {
        return DispatchQueue.main.async { result(FlutterError(code: "INVALID_HELPER_RESPONSE", message: nil, details: nil)) }
      }
      DispatchQueue.main.async { result(object) }
    }
  }

  private func ensureService(restart: Bool, result: @escaping FlutterResult) {
    do {
      if restart && (service.status == .enabled || service.status == .requiresApproval) {
        try service.unregister()
      }
      if service.status == .notRegistered || service.status == .notFound {
        try service.register()
      }
      if service.status == .requiresApproval {
        return result(FlutterError(code: "BACKGROUND_APPROVAL_REQUIRED", message: "Allow KeyLease in Login Items", details: nil))
      }
      if service.status != .enabled {
        return result(FlutterError(code: "SERVICE_NOT_FOUND", message: "The bundled KeyLease background service was not found", details: nil))
      }
      result(nil)
    } catch {
      let problem = error as NSError
      result(FlutterError(
        code: "SERVICE_REGISTRATION_FAILED",
        message: "Could not enable KeyLease in the background",
        details: ["domain": problem.domain, "code": problem.code]
      ))
    }
  }

  private func chooseVault(result: @escaping FlutterResult) {
    guard let window else { return result(nil) }
    let panel = NSOpenPanel()
    panel.canChooseDirectories = false
    panel.canChooseFiles = true
    panel.allowsMultipleSelection = false
    panel.beginSheetModal(for: window) { response in
      result(response == .OK ? panel.url?.path : nil)
    }
  }
}
