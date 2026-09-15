import SwiftUI

/// Master-password prompt — the Dart `locked` phase screen.
struct UnlockView: View {
    let app: AppController
    @State private var password = ""
    @State private var busy = false

    var body: some View {
        KLStateScreen(icon: "lock.fill", title: "Unlock KeyLease") {
            VStack(spacing: KL.Space.xl) {
                if let message = app.unlockMessage {
                    Text(message.title)
                        .foregroundStyle(KL.Colors.danger)
                        .font(.callout)
                }
                SecureField("Master password", text: $password)
                    .frame(maxWidth: 320)
                    .onSubmit { Task { await submit() } }
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
    }

    private func submit() async {
        busy = true
        defer { busy = false }
        _ = await app.unlock(password)
        password = ""
    }
}
