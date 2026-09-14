import SwiftUI

/// `repair_required`: the vault exists but the client token is missing —
/// re-register it with the master password (`mode: "repair_desktop_client"`).
struct RepairView: View {
    let app: AppController
    @State private var password = ""
    @State private var busy = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "wrench.and.screwdriver")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("Repair this Mac's access").font(.title2).bold()
            Text(
                "Your vault exists but this client is not registered. "
                    + "Enter the master password to re-register it."
            )
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 420)
            if let message = app.message {
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
                    Text("Repair")
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
        _ = await app.repairClient(password: password)
        password = ""
    }
}
