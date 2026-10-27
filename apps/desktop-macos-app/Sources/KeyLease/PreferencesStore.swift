import Foundation

import KeyLeaseCore

/// Non-secret UI preferences in `~/.keylease/ui.json`: pane widths, generator
/// settings, and per-device SSH key bindings.
@MainActor @Observable
final class PreferencesStore {
    private(set) var values: [String: JSONValue] = [:]
    private let url: URL

    init(url: URL? = nil) {
        self.url = url ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".keylease/ui.json")
    }

    func load() {
        guard let data = try? Data(contentsOf: url),
            let object = try? JSONDecoder()
                .decode(JSONValue.self, from: data).objectValue
        else { return }
        values = object
    }

    func save() {
        let directory = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        guard let data = try? JSONEncoder()
            .encode(JSONValue.object(values))
        else { return }
        try? data.write(to: url, options: .atomic)
    }

    // MARK: Pane geometry

    var sidebarWidth: Double {
        get { values["sidebar_width"]?.doubleValue ?? 0 }
        set { values["sidebar_width"] = .double(newValue); save() }
    }

    var listWidth: Double {
        get { values["list_width"]?.doubleValue ?? 0 }
        set { values["list_width"] = .double(newValue); save() }
    }

    // MARK: Password generator

    var passwordGenerator: PasswordGeneratorSettings {
        get {
            values["password_generator"].map(PasswordGeneratorSettings.init)
                ?? PasswordGeneratorSettings()
        }
        set {
            values["password_generator"] = .object(newValue.jsonObject)
            save()
        }
    }

    // MARK: SSH key bindings

    /// `ssh_key_bindings` — `"<vaultId>/<itemId>/<endpointId>" → key path`,
    /// per device because a private key path is meaningless elsewhere.
    private var sshBindings: [String: String] {
        values["ssh_key_bindings"]?.objectValue?
            .compactMapValues(\.stringValue) ?? [:]
    }

    func sshKeyBinding(itemId: String, endpointId: String, vaultId: String?)
        -> String?
    {
        sshBindings["\(vaultId ?? "unknown")/\(itemId)/\(endpointId)"]
    }

    /// Persists a binding and verifies it landed, mirroring the Dart
    /// `setSshKeyBinding` rollback-on-failure behaviour.
    func setSshKeyBinding(
        itemId: String, endpointId: String, vaultId: String?,
        path: String?
    ) throws {
        let key = "\(vaultId ?? "unknown")/\(itemId)/\(endpointId)"
        let previous = values["ssh_key_bindings"]
        var bindings = sshBindings
        if let path, !path.isEmpty {
            bindings[key] = path
        } else {
            bindings.removeValue(forKey: key)
        }
        values["ssh_key_bindings"] = .object(
            bindings.mapValues(JSONValue.string))
        save()
        // Verify the write survived — the Dart store re-reads the file.
        load()
        let persisted = sshBindings[key]
        let expected = (path?.isEmpty ?? true) ? nil : path
        if persisted != expected {
            values["ssh_key_bindings"] = previous
            throw RuntimeError(
                code: "PREFERENCES_FAILED",
                message: "The SSH key binding could not be saved on this device.")
        }
    }

    func removeSshBindingsForItem(_ itemId: String) {
        var bindings = sshBindings
        let marker = "/\(itemId)/"
        bindings = bindings.filter { !$0.key.contains(marker) }
        values["ssh_key_bindings"] = .object(
            bindings.mapValues(JSONValue.string))
        save()
    }
}

extension JSONValue {
    var doubleValue: Double? {
        switch self {
        case .double(let value): value
        case .int(let value): Double(value)
        case .uint(let value): Double(value)
        default: nil
        }
    }
}
