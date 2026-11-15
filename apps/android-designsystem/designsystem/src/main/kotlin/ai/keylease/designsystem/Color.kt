package ai.keylease.designsystem

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Brand colors. Fixed in both themes; use them for the mark, the splash and
 * brand material. App UI takes its colors from [KeyleaseColors] instead.
 */
object KeyleaseBrand {
    /** App-icon field, splash background; primary text in light theme. Never a button fill. */
    val Midnight = Color(0xFF071426)

    /** The symbol's gate and large fills. White text on it is 4.2:1: buttons use `primary`. */
    val GatewayBlue = Color(0xFF2F72FF)

    /** The access plane; the granted/connected signal on Midnight. Never text on light grounds. */
    val AccessMint = Color(0xFF36E3A2)

    /** Light background of brand surfaces. */
    val Cloud = Color(0xFFF5F8FC)

    /** Secondary text in brand material. In the app use `onSurfaceVariant`. */
    val Slate = Color(0xFF5E6B7C)

    /** Denied state on Midnight. In the app use `danger`. */
    val Denied = Color(0xFFFF5D6C)

    /** Pending state on Midnight. In the app use `warning`. */
    val Pending = Color(0xFFFFBE55)
}

/**
 * The app's color roles. Every text role reaches 4.5:1 on `background`,
 * `surface` and `surfaceRaised` in both themes; `outline` and `focusRing`
 * reach 3:1. State colors are always shown with a word or an icon.
 */
@Immutable
data class KeyleaseColors(
    /** Window background behind scrolling content. */
    val background: Color,
    /** App bars, bottom navigation, grouped lists. */
    val surface: Color,
    /** Cards, dialogs and sheets. */
    val surfaceRaised: Color,
    /** Primary text and icons. */
    val ink: Color,
    /** Labels, timestamps, helper text, section labels. */
    val onSurfaceVariant: Color,
    /** Borders of inputs, outlined buttons, selectable rows. */
    val outline: Color,
    /** Hairline dividers; never the only boundary of a control. */
    val outlineVariant: Color,
    /** Filled buttons, links, selection; text accent. */
    val primary: Color,
    /** Text and icons on `primary`. */
    val onPrimary: Color,
    /** Monogram tile and selected-row tint. */
    val markSurface: Color,
    /** Monogram letters. 3.8:1 on `markSurface` in light: decorative only. */
    val markForeground: Color,
    val success: Color,
    val successContainer: Color,
    val warning: Color,
    val warningContainer: Color,
    val danger: Color,
    val dangerContainer: Color,
    /** 2dp focus outline for keyboard and D-pad. */
    val focusRing: Color,
    /** Behind dialogs and bottom sheets. */
    val scrim: Color,
) {
    /** The color for a connection's health string, as the app reports it. */
    fun statusColor(health: String): Color = when (health) {
        "connected" -> success
        "degraded", "expired" -> warning
        "revoked", "disconnected" -> danger
        else -> warning
    }
}

val LightKeyleaseColors = KeyleaseColors(
    background = Color(0xFFFFFFFF),
    surface = Color(0xFFF8F9FC),
    surfaceRaised = Color(0xFFFFFFFF),
    ink = Color(0xFF071426),
    onSurfaceVariant = Color(0xFF4A5A70),
    outline = Color(0xFF7D8A9C),
    outlineVariant = Color(0xFFE3E8EF),
    primary = Color(0xFF1C65FF),
    onPrimary = Color(0xFFFFFFFF),
    markSurface = Color(0xFFEEF4FF),
    markForeground = Color(0xFF2F72FF),
    success = Color(0xFF1A7F47),
    successContainer = Color(0xFFEEF8F2),
    warning = Color(0xFF9A6207),
    warningContainer = Color(0xFFFBF0DC),
    danger = Color(0xFFB3261E),
    dangerContainer = Color(0xFFF9E3E1),
    focusRing = Color(0xFF2F72FF),
    scrim = Color(0xA3071426),
)

val DarkKeyleaseColors = KeyleaseColors(
    background = Color(0xFF0A0E14),
    surface = Color(0xFF10141C),
    surfaceRaised = Color(0xFF171C26),
    ink = Color(0xFFE6EBF2),
    onSurfaceVariant = Color(0xFF9AA6B6),
    outline = Color(0xFF657084),
    outlineVariant = Color(0xFF262D3A),
    primary = Color(0xFF6AA9F5),
    onPrimary = Color(0xFF08121F),
    markSurface = Color(0xFF212D3F),
    markForeground = Color(0xFF9CC7FA),
    success = Color(0xFF5EC98B),
    successContainer = Color(0xFF16302A),
    warning = Color(0xFFE0B062),
    warningContainer = Color(0xFF33291A),
    danger = Color(0xFFEF8079),
    dangerContainer = Color(0xFF3A1F22),
    focusRing = Color(0xFF9CC7FA),
    scrim = Color(0xB8000000),
)

val LocalKeyleaseColors = staticCompositionLocalOf { LightKeyleaseColors }
