import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var observerTokens: [NSObjectProtocol] = []
  private var securityScopedURLs: [URL] = []
  private var sensitivePasteboardChangeCount: Int?
  private var menuChannel: FlutterMethodChannel?

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
