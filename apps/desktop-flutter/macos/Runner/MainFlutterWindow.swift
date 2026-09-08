import Cocoa
import FlutterMacOS
import ServiceManagement
import UniformTypeIdentifiers
import Vision

class MainFlutterWindow: NSWindow {
  private var observerTokens: [NSObjectProtocol] = []
  private var securityScopedURLs: [URL] = []
  private var sensitivePasteboardChangeCount: Int?
  private var menuChannel: FlutterMethodChannel?
  private var runtimeBridge: AnyObject?

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
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            do {
              try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])
              let payload = (request.results ?? [])
                .compactMap { $0.payloadStringValue }
                .first { $0.lowercased().hasPrefix("otpauth://totp/") }
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
