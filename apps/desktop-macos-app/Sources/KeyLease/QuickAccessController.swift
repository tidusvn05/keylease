import AppKit
import Carbon.HIToolbox
import SwiftUI

/// The menu-bar status item, its quick-access popover and the ⌥⌘K
/// hotkey that toggles it. Built on `NSStatusItem`/`NSPopover` because
/// `MenuBarExtra` offers no programmatic presentation — which a global
/// hotkey needs.
@MainActor
final class QuickAccessController: NSObject {
    private weak var app: AppController?
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var hotkey: GlobalHotKey?

    init(app: AppController) { self.app = app }

    func install() {
        guard statusItem == nil, let app else { return }

        let popover = NSPopover()
        popover.behavior = .transient
        popover.contentSize = NSSize(width: 340, height: 420)
        popover.contentViewController = NSHostingController(
            rootView: QuickAccessView(
                app: app,
                presented: Binding(
                    get: { popover.isShown },
                    set: { if !$0 { popover.performClose(nil) } }))
                .tint(KL.Colors.accent))
        self.popover = popover

        let item = NSStatusBar.system.statusItem(
            withLength: NSStatusItem.variableLength)
        item.button?.image = NSImage(
            systemSymbolName: "key.fill",
            accessibilityDescription: "KeyLease Quick Access")
        item.button?.target = self
        item.button?.action = #selector(togglePopover)
        statusItem = item

        hotkey = GlobalHotKey(
            keyCode: UInt32(kVK_ANSI_K),
            modifiers: UInt32(cmdKey | optionKey)
        ) { [weak self] in
            Task { @MainActor in self?.togglePopover() }
        }
    }

    @objc private func togglePopover() {
        guard let popover, let button = statusItem?.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            NSApp.activate()
            popover.show(
                relativeTo: button.bounds, of: button,
                preferredEdge: .minY)
        }
    }
}
