import SwiftUI

/// `repair_required`: the vault exists but the client token is missing —
/// re-register it with the master password (`mode: "repair_desktop_client"`).
struct RepairView: View {
    let app: AppController
    @State private var password = ""
    @State private var busy = false

    var body: some View {
        KLStateScreen(
            icon: "wrench.and.screwdriver",
            title: "Repair this Mac's access",
            detail:
                "Your vault exists but this client is not registered. "
                + "Enter the master password to re-register it."
        ) {
            VStack(spacing: KL.Space.xl) {
                if let message = app.message {
                    Text(message.title)
                        .foregroundStyle(KL.Colors.danger)
                        .font(.callout)
                }
                KLSecureField(
                    label: "Master password", text: $password
                ) {
                    Task { await submit() }
                }
                .frame(width: 320)
                HStack(spacing: KL.Space.m) {
                    KLButton(
                        title: "Repair", role: .primary, prominent: true)
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
        _ = await app.repairClient(password: password)
        password = ""
    }
}
