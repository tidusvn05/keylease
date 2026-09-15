import AppKit
import SwiftUI

// MARK: - Design tokens (`brand/BRAND.md` + `keylease_tokens.dart`)

/// The single place deciding how KeyLease looks — colors, spacing, radii
/// and the shared control chrome. Values mirror the Flutter token set so
/// both apps read as one product.
enum KL {
    enum Colors {
        /// Gateway Blue — primary actions, focus, the mark. The dark
        /// variant is the lightened blue the Flutter tokens use for
        /// readability on Midnight surfaces.
        static let accent = Color(
            light: 0x2F72FF, dark: 0x6AA9F5)
        /// Accent tuned for text/icons on surfaces (>= 4.5:1 contrast).
        static let accentText = Color(
            light: 0x1C65FF, dark: 0x6AA9F5)
        /// Text/icon color drawn on top of `accent` fills.
        static let onAccent = Color(
            light: 0xFFFFFF, dark: 0x08121F)

        /// Access Mint family — granted/connected signals.
        static let success = Color(
            light: 0x1A7F47, dark: 0x5EC98B)
        /// Pending — waiting on a human decision.
        static let warning = Color(
            light: 0x9A6207, dark: 0xE0B062)
        /// Denied — destructive and denied states only (BRAND.md).
        static let danger = Color(
            light: 0xB3261E, dark: 0xEF8079)

        /// Monogram tile: tinted surface + accent glyph (the
        /// markSurface/markForeground tokens).
        static let markSurface = Color(
            light: 0x2F72FF, dark: 0x6AA9F5,
            lightAlpha: 0.08, darkAlpha: 0.14)
        static let markForeground = Color(
            light: 0x2F72FF, dark: 0x9CC7FA)

        /// Card fill on top of the window background.
        static let cardFill = Color(nsColor: .controlBackgroundColor)
        /// Hairline around cards and field groups.
        static let cardStroke = Color.primary.opacity(0.09)
        /// Subtle fill behind guidance blocks and code samples.
        static let insetFill = Color.primary.opacity(0.035)

        /// Banner backgrounds per severity.
        static func bannerFill(_ tone: BannerTone) -> Color {
            tone.color.opacity(0.09)
        }
        static func bannerStroke(_ tone: BannerTone) -> Color {
            tone.color.opacity(0.32)
        }
    }

    enum Space {
        static let xxs: CGFloat = 2
        static let xs: CGFloat = 4
        static let s: CGFloat = 6
        static let m: CGFloat = 8
        static let l: CGFloat = 10
        static let xl: CGFloat = 12
        static let xxl: CGFloat = 16
        static let xxxl: CGFloat = 20
        static let xxxxl: CGFloat = 24
    }

    enum Radius {
        /// Small controls, icon-button hover.
        static let small: CGFloat = 6
        /// Inset blocks (code, notes).
        static let medium: CGFloat = 8
        /// Cards and field groups.
        static let card: CGFloat = 10
    }
}

/// Severity of a `MessageBanner`.
enum BannerTone {
    case info, warning, error

    var color: Color {
        switch self {
        case .info: KL.Colors.accentText
        case .warning: KL.Colors.warning
        case .error: KL.Colors.danger
        }
    }

    var icon: String {
        switch self {
        case .info: "info.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .error: "exclamationmark.octagon.fill"
        }
    }
}

// MARK: - Adaptive color helper

extension Color {
    /// sRGB hex color that adapts to light/dark appearance.
    init(
        light: UInt32, dark: UInt32,
        lightAlpha: Double = 1, darkAlpha: Double = 1
    ) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua])
                == .darkAqua
            return NSColor(
                kl_hex: isDark ? dark : light,
                alpha: isDark ? darkAlpha : lightAlpha)
        })
    }
}

extension NSColor {
    convenience init(kl_hex: UInt32, alpha: Double = 1) {
        self.init(
            srgbRed: CGFloat((kl_hex >> 16) & 0xFF) / 255,
            green: CGFloat((kl_hex >> 8) & 0xFF) / 255,
            blue: CGFloat(kl_hex & 0xFF) / 255,
            alpha: alpha)
    }
}

// MARK: - Buttons

/// The role a button plays — the only decision call sites make. Maps to
/// native chrome plus the brand tint so every button in the app matches.
enum KLButtonRole {
    /// Filled Gateway Blue — the one action the screen wants taken.
    case primary
    /// Bordered default — secondary actions.
    case secondary
    /// Bordered with the Denied color — destructive/negative actions.
    case destructive
    /// Text-only accent — low-emphasis navigation actions.
    case ghost
}

/// A `Button` with a `KLButtonRole` instead of ad-hoc `.buttonStyle` +
/// `.controlSize` + `.tint` combinations.
struct KLButton: View {
    let title: String
    var icon: String? = nil
    var role: KLButtonRole = .secondary
    var prominent = false
    var action: () -> Void

    @ViewBuilder private var label: some View {
        if let icon {
            Label(title, systemImage: icon)
        } else {
            Text(title)
        }
    }

    /// One branch per role — the concrete `PrimitiveButtonStyle` differs
    /// per branch, so it cannot be a single stored style.
    @ViewBuilder private var styled: some View {
        switch role {
        case .primary:
            Button(action: action) { label }
                .buttonStyle(.borderedProminent)
                .tint(KL.Colors.accent)
        case .secondary:
            Button(action: action) { label }
                .buttonStyle(.bordered)
        case .destructive:
            Button(action: action) { label }
                .buttonStyle(.bordered)
                .foregroundStyle(KL.Colors.danger)
        case .ghost:
            Button(action: action) { label }
                .buttonStyle(.borderless)
                .foregroundStyle(KL.Colors.accentText)
        }
    }

    var body: some View {
        styled.modifier(ProminentSize(prominent: prominent))
    }
}

/// `.controlSize(.large)` is only valid on some styles — keep it opt-in.
private struct ProminentSize: ViewModifier {
    let prominent: Bool
    func body(content: Content) -> some View {
        if prominent {
            content.controlSize(.large)
        } else {
            content
        }
    }
}

/// Icon-only button with a consistent 24pt target and a hover wash —
/// replaces ad-hoc `.borderless` image buttons.
struct KLIconButton: View {
    let label: String
    let icon: String
    var danger = false
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .frame(width: 24, height: 24)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(danger ? KL.Colors.danger : Color.secondary)
        .background(
            RoundedRectangle(cornerRadius: KL.Radius.small)
                .fill(Color.primary.opacity(hovering ? 0.09 : 0)))
        .onHover { hovering = $0 }
        .help(label)
        .accessibilityLabel(label)
    }
}

// MARK: - Surfaces

/// A filled card — controlBackground with a hairline, one radius for the
/// whole app.
struct KLCard<Content: View>: View {
    var padding: CGFloat = KL.Space.xl
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardBackground)
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: KL.Radius.card)
            .fill(KL.Colors.cardFill)
            .overlay(
                RoundedRectangle(cornerRadius: KL.Radius.card)
                    .stroke(KL.Colors.cardStroke))
    }
}

/// Inset block for code/hand-off text — subtle fill instead of a card.
struct KLInsetBlock<Content: View>: View {
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(KL.Space.xl)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: KL.Radius.medium)
                    .fill(KL.Colors.insetFill)
                    .overlay(
                        RoundedRectangle(cornerRadius: KL.Radius.medium)
                            .stroke(KL.Colors.cardStroke)))
    }
}

// MARK: - State screens

/// Centered empty/locked/setup layout — brand tile, title, detail, then
/// caller-provided fields and actions.
struct KLStateScreen<Content: View>: View {
    let icon: String
    let title: String
    var detail: String? = nil
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(spacing: KL.Space.xxl) {
            Image(systemName: icon)
                .font(.system(size: 26, weight: .medium))
                .foregroundStyle(KL.Colors.onAccent)
                .frame(width: 56, height: 56)
                .background(
                    RoundedRectangle(cornerRadius: 14)
                        .fill(KL.Colors.accent.gradient))
            VStack(spacing: KL.Space.s) {
                Text(title).font(.title2.weight(.semibold))
                if let detail {
                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 440)
                }
            }
            content()
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

extension KLStateScreen where Content == EmptyView {
    init(icon: String, title: String, detail: String? = nil) {
        self.init(icon: icon, title: title, detail: detail) {
            EmptyView()
        }
    }
}
