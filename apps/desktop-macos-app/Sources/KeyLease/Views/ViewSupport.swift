import AppKit
import SwiftUI

import KeyLeaseCore

// MARK: - Dialog helpers

/// Synchronous destructive-action confirmation — the Flutter `confirm()`
/// dialog. NSAlert gives a real modal on macOS.
@MainActor
func confirmAction(
    title: String,
    message: String,
    confirmLabel: String,
    destructive: Bool = false
) -> Bool {
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = message
    alert.alertStyle = destructive ? .critical : .warning
    alert.addButton(withTitle: confirmLabel)
    alert.addButton(withTitle: "Cancel")
    if destructive,
        let button = alert.buttons.first
    {
        button.hasDestructiveAction = true
    }
    return alert.runModal() == .alertFirstButtonReturn
}

// MARK: - Shared chrome

/// `SectionLabel` — the small heading above a field group.
struct SectionLabel: View {
    let title: String
    var body: some View {
        Text(title)
            .font(.callout.weight(.semibold))
            .foregroundStyle(.secondary)
    }
}

/// `KeyLeaseMark` — the rounded monogram tile on list rows and the detail
/// header.
struct MonogramMark: View {
    let text: String
    var large = false

    var body: some View {
        let side: CGFloat = large ? 44 : 30
        Text(text)
            .font(.system(
                size: large ? 15 : 11, weight: .semibold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: side, height: side)
            .background(
                RoundedRectangle(cornerRadius: side * 0.28)
                    .fill(Color.accentColor.gradient))
    }
}

/// `MessageBanner` — inline error/info strip with retry/dismiss.
struct MessageBanner: View {
    let message: UserMessage
    var actionLabel: String? = nil
    var onAction: (() -> Void)? = nil
    var onDismiss: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(message.title).font(.callout.weight(.medium))
                if let detail = message.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            if let actionLabel, let onAction {
                Button(actionLabel, action: onAction)
                    .controlSize(.small)
            }
            if let onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.orange.opacity(0.08))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.orange.opacity(0.35))))
    }
}

/// `GuidanceCard` — the "About this template" block under pickers.
struct GuidanceCard: View {
    let title: String
    let summary: String
    let useWhen: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: "info.circle")
                .font(.callout.weight(.medium))
            Text(summary).font(.callout)
            Text(useWhen)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 9)
                .fill(Color.primary.opacity(0.04))
                .overlay(
                    RoundedRectangle(cornerRadius: 9)
                        .stroke(Color.primary.opacity(0.12))))
    }
}

// MARK: - Detail field rows (`DetailField` / `SecretField` / `FieldGroup`)

/// A labeled row in the detail pane, with optional trailing icon buttons.
struct DetailRow<Actions: View>: View {
    let label: String
    let value: String
    var accent = false
    var onPress: (() -> Void)? = nil
    @ViewBuilder var actions: () -> Actions

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .leading)
            Group {
                if let onPress {
                    Button(action: onPress) {
                        Text(value.isEmpty ? "—" : value)
                            .underline(false)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.tint)
                } else {
                    Text(value.isEmpty ? "—" : value)
                        .foregroundStyle(accent ? AnyShapeStyle(.tint)
                            : AnyShapeStyle(.primary))
                }
            }
            .textSelection(.enabled)
            .lineLimit(3)
            .truncationMode(.middle)
            Spacer(minLength: 8)
            actions()
        }
        .padding(.vertical, 6)
    }
}

extension DetailRow where Actions == EmptyView {
    init(
        label: String, value: String, accent: Bool = false,
        onPress: (() -> Void)? = nil
    ) {
        self.init(
            label: label, value: value, accent: accent, onPress: onPress
        ) { EmptyView() }
    }
}

/// A concealed value with reveal/hide/copy — the Dart `SecretField`.
struct SecretRow: View {
    let label: String
    /// The revealed value, or nil while masked.
    let revealed: String?
    /// Server-side hint such as `••••1234`.
    var hint: String? = nil
    var onReveal: () async -> Void
    var onHide: () -> Void
    var onCopy: () -> Void
    @State private var busy = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .leading)
            if let revealed {
                Text(revealed)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            } else {
                Text(hint ?? "••••••••")
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            if busy {
                ProgressView().controlSize(.small)
            } else {
                Button {
                    if revealed == nil {
                        busy = true
                        Task {
                            await onReveal()
                            busy = false
                        }
                    } else {
                        onHide()
                    }
                } label: {
                    Image(systemName: revealed == nil ? "eye" : "eye.slash")
                }
                .buttonStyle(.borderless)
                .help(revealed == nil ? "Reveal" : "Hide")
                Button(action: onCopy) {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy (clears after 30 s)")
            }
        }
        .padding(.vertical, 6)
    }
}

/// Wraps rows in the bordered card the Dart `FieldGroup` draws.
struct FieldGroup<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        VStack(spacing: 0) {
            content()
        }
        .padding(.horizontal, 12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.primary.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.primary.opacity(0.1))))
    }
}

/// A small icon-only button — the Dart `IconAction`.
struct IconAction: View {
    let label: String
    let icon: String
    var danger = false
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .foregroundStyle(danger ? .red : .primary)
        }
        .buttonStyle(.borderless)
        .help(label)
        .accessibilityLabel(label)
    }
}

// MARK: - Time formatting (`friendlyTime` in activity_page.dart)

func friendlyTime(_ when: Date?) -> String {
    guard let when else { return "Unknown time" }
    let delta = Date().timeIntervalSince(when)
    if delta < 60 { return "Just now" }
    if delta < 3600 { return "\(Int(delta / 60)) min ago" }
    if delta < 86400 { return "\(Int(delta / 3600)) hr ago" }
    if delta < 7 * 86400 { return "\(Int(delta / 86400)) days ago" }
    let calendar = Calendar.current
    let parts = calendar.dateComponents([.year, .month, .day], from: when)
    return String(
        format: "%04d-%02d-%02d",
        parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
}
