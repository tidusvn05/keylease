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

/// `SectionLabel` — the small caps heading above a field group.
struct SectionLabel: View {
    let title: String
    var body: some View {
        Text(title.uppercased())
            .font(.caption.weight(.semibold))
            .tracking(0.6)
            .foregroundStyle(.secondary)
    }
}

/// `KeyLeaseMark` — the rounded monogram tile on list rows and the detail
/// header. Tinted brand surface + accent glyph, per the mark tokens.
struct MonogramMark: View {
    let text: String
    var large = false

    var body: some View {
        let side: CGFloat = large ? 44 : 30
        Text(text)
            .font(.system(
                size: large ? 15 : 11, weight: .semibold, design: .rounded))
            .foregroundStyle(KL.Colors.markForeground)
            .frame(width: side, height: side)
            .background(
                RoundedRectangle(cornerRadius: side * 0.28)
                    .fill(KL.Colors.markSurface)
                    .overlay(
                        RoundedRectangle(cornerRadius: side * 0.28)
                            .stroke(KL.Colors.cardStroke)))
    }
}

/// `MessageBanner` — inline error/info strip with retry/dismiss.
struct MessageBanner: View {
    let message: UserMessage
    var tone: BannerTone = .error
    var actionLabel: String? = nil
    var onAction: (() -> Void)? = nil
    var onDismiss: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: KL.Space.l) {
            Image(systemName: tone.icon)
                .foregroundStyle(tone.color)
            VStack(alignment: .leading, spacing: KL.Space.xxs) {
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
                KLButton(title: actionLabel, action: onAction)
                    .controlSize(.small)
            }
            if let onDismiss {
                KLIconButton(label: "Dismiss", icon: "xmark",
                             action: onDismiss)
            }
        }
        .padding(KL.Space.l)
        .background(
            RoundedRectangle(cornerRadius: KL.Radius.medium)
                .fill(KL.Colors.bannerFill(tone))
                .overlay(
                    RoundedRectangle(cornerRadius: KL.Radius.medium)
                        .stroke(KL.Colors.bannerStroke(tone))))
    }
}

/// `GuidanceCard` — the "About this template" block under pickers.
struct GuidanceCard: View {
    let title: String
    let summary: String
    let useWhen: String

    var body: some View {
        VStack(alignment: .leading, spacing: KL.Space.s) {
            Label(title, systemImage: "info.circle")
                .font(.callout.weight(.medium))
                .foregroundStyle(KL.Colors.accentText)
            Text(summary).font(.callout)
            Text(useWhen)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(KL.Space.xl)
        .background(
            RoundedRectangle(cornerRadius: KL.Radius.medium)
                .fill(KL.Colors.insetFill)
                .overlay(
                    RoundedRectangle(cornerRadius: KL.Radius.medium)
                        .stroke(KL.Colors.cardStroke)))
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
                KLIconButton(
                    label: revealed == nil ? "Reveal" : "Hide",
                    icon: revealed == nil ? "eye" : "eye.slash")
                {
                    if revealed == nil {
                        busy = true
                        Task {
                            await onReveal()
                            busy = false
                        }
                    } else {
                        onHide()
                    }
                }
                KLIconButton(
                    label: "Copy (clears after 30 s)",
                    icon: "doc.on.doc",
                    action: onCopy)
            }
        }
        .padding(.vertical, 6)
    }
}

/// Publishes the `NSWindow` a view lives in — SwiftUI keeps no window
/// handle, and the quick-access popover needs one to bring the existing
/// main window forward instead of spawning a second.
struct WindowAccessor: NSViewRepresentable {
    let onResolve: (NSWindow?) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { onResolve(view.window) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async { onResolve(nsView.window) }
    }
}

/// The one secure field language across unlock/onboarding/repair —
/// label above, rounded border — matching the editor's `labeledField`
/// pattern instead of a lone placeholder inside the field.
struct KLSecureField: View {
    let label: String
    @Binding var text: String
    var focused: FocusState<Bool>.Binding? = nil
    var onSubmit: (() -> Void)? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: KL.Space.xs) {
            Text(label).font(.callout)
            field
                .textFieldStyle(.roundedBorder)
                .onSubmit { onSubmit?() }
        }
    }

    @ViewBuilder private var field: some View {
        if let focused {
            SecureField("", text: $text).focused(focused)
        } else {
            SecureField("", text: $text)
        }
    }
}

/// Wraps rows in the card the Dart `FieldGroup` draws.
struct FieldGroup<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        VStack(spacing: 0) {
            content()
        }
        .padding(.horizontal, KL.Space.xl)
        .background(
            RoundedRectangle(cornerRadius: KL.Radius.card)
                .fill(KL.Colors.cardFill)
                .overlay(
                    RoundedRectangle(cornerRadius: KL.Radius.card)
                        .stroke(KL.Colors.cardStroke)))
    }
}

/// A small icon-only button — the Dart `IconAction`, now on KL chrome.
typealias IconAction = KLIconButton

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
