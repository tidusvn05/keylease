import SwiftUI

/// Master-password prompt — the Dart `locked` phase screen.
struct UnlockView: View {
    let app: AppController
    @State private var password = ""
    @State private var busy = false
    @FocusState private var passwordFocused: Bool

    private var vaultName: String? {
        app.vaultProfiles.first(where: \.active)?.name
    }

    var body: some View {
        KLStateScreen(
            icon: "lock.fill", title: "Unlock KeyLease",
            detail: vaultName.map { "Vault: \($0)" })
        {
            VStack(spacing: KL.Space.xl) {
                if let message = app.unlockMessage {
                    Text(message.title)
                        .foregroundStyle(KL.Colors.danger)
                        .font(.callout)
                }
                KLSecureField(
                    label: "Master password", text: $password,
                    focused: $passwordFocused
                ) {
                    Task { await submit() }
                }
                .frame(width: 320)
                HStack(spacing: KL.Space.m) {
                    KLButton(
                        title: "Unlock", role: .primary, prominent: true)
                    {
                        Task { await submit() }
                    }
                    .disabled(password.isEmpty || busy)
                    .keyboardShortcut(.defaultAction)
                    if busy {
                        ProgressView().controlSize(.small)
                    }
                }
            }
        }
        .onAppear {
            // Focus may need a beat while the window finishes appearing.
            DispatchQueue.main.async { passwordFocused = true }
        }
    }

    private func submit() async {
        busy = true
        defer { busy = false }
        _ = await app.unlock(password)
        password = ""
    }
}
