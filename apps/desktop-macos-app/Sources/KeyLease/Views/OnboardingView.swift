import SwiftUI

import KeyLeaseCore

/// First-run screen — `OnboardingScreen` in `phase_screens.dart`: create a
/// fresh vault or provision from an existing file (KDBX / 1PUX / KeyLease
/// backup / earlier KeyLease database).
struct OnboardingView: View {
    let app: AppController
    @State private var password = ""
    @State private var confirm = ""
    @State private var sourcePath: String?
    @State private var sourceKind: String?
    @State private var sourcePassword = ""
    @State private var differentPassword = false
    @State private var acknowledgePlaintext = false
    @State private var error: String?
    @State private var busy = false

    private var importing: Bool { sourcePath != nil }
    private var needsSourcePassword: Bool { sourceKind == "kdbx" }
    private var needsTargetPassword: Bool {
        !needsSourcePassword || differentPassword
    }
    private var passwordsMatch: Bool {
        !password.isEmpty && password == confirm
    }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "key.fill")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text(importing ? "Bring your vault to KeyLease"
                : "Welcome to KeyLease")
                .font(.title2).bold()
            Text(
                importing
                    ? "Your original file stays unchanged. KeyLease "
                        + "creates a managed copy on this Mac."
                    : "Create a new encrypted vault, or use one you "
                        + "already have.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)

            if let message = app.message {
                Text(message.title).foregroundStyle(.red).font(.callout)
            }
            if let error {
                Text(error).foregroundStyle(.red).font(.callout)
            }

            if !importing {
                Button("Create a new vault") {
                    sourcePath = nil
                    sourceKind = nil
                }
                Button("Use an existing vault") { choose() }
                if let legacy = app.legacyDatabase {
                    Button(
                        "Continue with the vault from an earlier KeyLease "
                            + "setup")
                    {
                        Task { await adopt(legacy) }
                    }
                    .buttonStyle(.link)
                }
            } else {
                Text(sourcePath!)
                    .lineLimit(2).truncationMode(.middle)
                    .font(.caption)
                    .frame(maxWidth: 420)
                Button("Choose another file") {
                    sourcePath = nil
                    sourceKind = nil
                }
            }

            if needsSourcePassword {
                SecureField(
                    "Existing vault password", text: $sourcePassword)
                    .frame(maxWidth: 320)
                Toggle(
                    "Use a different password in KeyLease",
                    isOn: $differentPassword)
            }
            if needsTargetPassword {
                SecureField(
                    importing ? "KeyLease password" : "Master password",
                    text: $password)
                    .frame(maxWidth: 320)
                SecureField("Confirm password", text: $confirm)
                    .frame(maxWidth: 320)
                if !confirm.isEmpty && !passwordsMatch {
                    Text("Passwords do not match")
                        .foregroundStyle(.red).font(.callout)
                }
            }
            if sourceKind == "onepux" {
                Toggle(
                    "I understand this export may contain plaintext "
                        + "secrets",
                    isOn: $acknowledgePlaintext)
            }

            Button {
                Task { await submit() }
            } label: {
                if busy {
                    ProgressView().controlSize(.small)
                } else {
                    Text(importing ? "Import and continue" : "Create vault")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(busy)

            Text("KeyLease stores its managed files privately in "
                + "~/.keylease.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(40)
    }

    private func choose() {
        guard let path = app.chooseVaultSource() else { return }
        Task { await adopt(path) }
    }

    private func adopt(_ path: String) async {
        busy = true
        defer { busy = false }
        do {
            let inspected = try await app.inspectSource(path: path)
            sourcePath = path
            sourceKind = inspected["kind"]?.stringValue
            error = nil
        } catch {
            self.error = UserMessage(error).title
        }
    }

    private func submit() async {
        let targetPassword = needsSourcePassword && !differentPassword
            ? sourcePassword : password
        guard !targetPassword.isEmpty,
            !needsTargetPassword || passwordsMatch
        else {
            error = "Enter matching passwords to continue."
            return
        }
        if sourceKind == "onepux", !acknowledgePlaintext {
            error = "Confirm that this export may contain plaintext "
                + "secrets."
            return
        }
        error = nil
        busy = true
        defer { busy = false }
        var request: [String: JSONValue] = [
            "password": .string(targetPassword)
        ]
        if let kind = sourceKind, let sourcePath {
            request["source_path"] = .string(sourcePath)
            switch kind {
            case "keylease_database":
                request["mode"] = .string("adopt_keylease_database")
            case "keylease_backup":
                request["mode"] = .string("restore_keylease_backup")
            case "kdbx":
                request["mode"] = .string("import_kdbx")
                request["source_password"] = .string(sourcePassword)
            default:
                request["mode"] = .string("import_onepux")
                request["acknowledge_plaintext"] = .bool(true)
            }
        } else {
            request["mode"] = .string("create")
        }
        _ = await app.provision(.object(request))
        password = ""
        confirm = ""
        sourcePassword = ""
    }
}
