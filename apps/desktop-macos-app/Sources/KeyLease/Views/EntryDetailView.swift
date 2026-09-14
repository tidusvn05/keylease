import Foundation
import SwiftUI

import KeyLeaseCore

/// Selected entry — renders `entries_view` fields; concealed values stay
/// hidden until an explicit `entries_reveal` (the Dart reveal flow).
struct EntryDetailView: View {
    let app: AppController

    var body: some View {
        if let detail = app.vault.detail {
            List {
                Section {
                    LabeledContent("Title", value: detail.metadata.title)
                    if let username = detail.metadata.username {
                        LabeledContent("Username", value: username)
                    }
                    ForEach(detail.fields, id: \.id) { field in
                        FieldRow(field: field, app: app)
                    }
                }
                if let totp = app.vault.totp {
                    Section("One-time code") {
                        HStack {
                            Text(totp)
                                .font(.title3.monospaced())
                                .textSelection(.enabled)
                            Button {
                                app.security.copySensitive(totp)
                            } label: {
                                Image(systemName: "doc.on.doc")
                            }
                            .buttonStyle(.borderless)
                            .help("Copy (clears after 30 s)")
                        }
                    }
                }
                if detail.hasNotes {
                    Section("Notes") {
                        Text("Entry has notes — note bodies arrive with the "
                            + "editor port.")
                            .foregroundStyle(.secondary)
                    }
                }
                if !detail.tags.isEmpty {
                    Section("Tags") {
                        Text(detail.tags.joined(separator: ", "))
                    }
                }
            }
            .navigationTitle(detail.metadata.title)
            .toolbar {
                if detail.metadata.hasTotp {
                    Button {
                        Task { await app.vault.loadTotp() }
                    } label: {
                        Label("TOTP", systemImage: "timer")
                    }
                }
                Button {
                    Task { await app.vault.loadDetail() }
                } label: {
                    Label("Reload", systemImage: "arrow.clockwise")
                }
            }
        } else {
            ProgressView()
        }
    }
}

private struct FieldRow: View {
    let field: FieldView
    let app: AppController

    var body: some View {
        LabeledContent {
            HStack {
                if let revealed = app.vault.revealed[field.id] {
                    Text(revealed)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button {
                        app.security.copySensitive(revealed)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy (clears after 30 s)")
                } else if let value = field.value {
                    Text(display(value))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                } else if field.hasValue {
                    Button {
                        Task { await app.vault.reveal(field) }
                    } label: {
                        Label("Reveal", systemImage: "eye")
                    }
                    .buttonStyle(.borderless)
                } else {
                    Text("—").foregroundStyle(.secondary)
                }
            }
        } label: {
            Text(field.label)
        }
    }

    private func display(_ value: FieldValue) -> String {
        switch value {
        case .text(let v): v.value
        case .concealed(let v): v.value
        case .url(let v): v.value
        case .email(let v): v.value
        case .phone(let v): v.value
        case .number(let v): String(v.value)
        case .date(let v): v.value
        case .monthYear(let v): "\(v.value.month)/\(v.value.year)"
        case .boolean(let v): v.value ? "Yes" : "No"
        case .totp: "TOTP configured"
        case .keyPair(let v): v.value.`public`
        case .certificate(let v): v.value
        case .attachmentRef(let v): v.value
        case .reference(let v): v.value
        case .address(let v):
            [v.value.street, v.value.city, v.value.state, v.value.postalCode,
             v.value.country]
                .filter { !$0.isEmpty }.joined(separator: ", ")
        case .opaqueJson(let v):
            (try? JSONEncoder().encode(v.value))
                .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        }
    }
}
