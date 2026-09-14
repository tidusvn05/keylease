import SwiftUI

/// Master-password prompt — the Dart `locked` phase screen.
struct UnlockView: View {
    let app: AppController
    @State private var password = ""
    @State private var busy = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("Unlock KeyLease").font(.title2).bold()
            if let message = app.unlockMessage {
                Text(message.title)
                    .foregroundStyle(.red)
                    .font(.callout)
            }
            SecureField("Master password", text: $password)
                .frame(maxWidth: 320)
                .onSubmit { Task { await submit() } }
            Button {
                Task { await submit() }
            } label: {
                if busy {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Unlock")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || busy)
        }
        .padding(40)
    }

    private func submit() async {
        busy = true
        defer { busy = false }
        _ = await app.unlock(password)
        password = ""
    }
}
