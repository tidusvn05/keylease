import Carbon.HIToolbox

/// A system-wide hotkey through Carbon `RegisterEventHotKey` — unlike
/// `NSEvent` global monitors this works without accessibility or
/// input-monitoring permission. Used for ⌥⌘K quick access.
final class GlobalHotKey {
    private var hotKeyRef: EventHotKeyRef?
    /// Written once at install, read on the main runloop by the Carbon
    /// event handler — safe to share unsynchronized.
    nonisolated(unsafe) private static var action: (() -> Void)?

    init(keyCode: UInt32, modifiers: UInt32, action: @escaping () -> Void) {
        GlobalHotKey.action = action
        var spec = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(
            GetApplicationEventTarget(),
            { _, _, _ -> OSStatus in
                GlobalHotKey.action?()
                return noErr
            }, 1, &spec, nil, nil)
        RegisterEventHotKey(
            keyCode, modifiers,
            // 'KLEA' — KeyLease's hotkey signature, id 1.
            EventHotKeyID(signature: 0x4B4C4541, id: 1),
            GetApplicationEventTarget(), 0, &hotKeyRef)
    }

    deinit {
        if let hotKeyRef { UnregisterEventHotKey(hotKeyRef) }
    }
}
