import SwiftUI

/// First-run screen — milestone 1 supports `mode: "create"` only; import
/// paths (KDBX/1PUX/backup) land with the feature port.
struct OnboardingView: View {
    let app: AppController
    @State private var password = ""
    @State private var confirm = ""
    @State private var busy = false

    private var passwordsMatch: Bool {
        !password.isEmpty && password == confirm
    }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "key.fill")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("Set up KeyLease").font(.title2).bold()
            Text("Create a master password for your new vault.")
                .foregroundStyle(.secondary)
            if let message = app.message {
                Text(message.title)
                    .foregroundStyle(.red)
                    .font(.callout)
            }
            SecureField("Master password", text: $password)
                .frame(maxWidth: 320)
            SecureField("Confirm password", text: $confirm)
                .frame(maxWidth: 320)
            if !confirm.isEmpty && !passwordsMatch {
                Text("Passwords do not match")
                    .foregroundStyle(.red)
                    .font(.callout)
            }
            Button {
                Task { await submit() }
            } label: {
                if busy {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Create vault")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!passwordsMatch || busy)
        }
        .padding(40)
    }

    private func submit() async {
        busy = true
        defer { busy = false }
        _ = await app.provisionNewVault(password: password)
        password = ""
        confirm = ""
    }
}
