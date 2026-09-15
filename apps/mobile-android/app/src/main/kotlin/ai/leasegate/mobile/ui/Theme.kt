package ai.leasegate.mobile.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * KeyLease design tokens — the Compose port of `KeyLeaseTokens`.
 *
 * Gateway Blue (#2f72ff) is the brand accent. On dark surfaces the readable
 * variant is the lightened #6aa9f5 — the same split the Flutter tokens make.
 */
data class KeyleaseColors(
    val accent: Color,
    val accentText: Color,
    val onAccent: Color,
    val success: Color,
    val warning: Color,
    val danger: Color,
    val markSurface: Color,
    val markForeground: Color,
) {
    fun statusColor(health: String): Color = when (health) {
        "connected" -> success
        "degraded", "expired" -> warning
        "revoked", "disconnected" -> danger
        else -> warning
    }
}

val LightKeyleaseColors = KeyleaseColors(
    accent = Color(0xff2f72ff),
    accentText = Color(0xff1c65ff),
    onAccent = Color(0xffffffff),
    success = Color(0xff1a7f47),
    warning = Color(0xff9a6207),
    danger = Color(0xffb3261e),
    markSurface = Color(0x142f72ff),
    markForeground = Color(0xff2f72ff),
)

val DarkKeyleaseColors = KeyleaseColors(
    accent = Color(0xff6aa9f5),
    accentText = Color(0xff6aa9f5),
    onAccent = Color(0xff08121f),
    success = Color(0xff5ec98b),
    warning = Color(0xffe0b062),
    danger = Color(0xffef8079),
    markSurface = Color(0x1f6aa9f5),
    markForeground = Color(0xff9cc7fa),
)

val LocalKeyleaseColors = staticCompositionLocalOf { LightKeyleaseColors }

private val lightScheme = lightColorScheme(
    primary = Color(0xff1c65ff),
    onPrimary = Color(0xffffffff),
    secondary = Color(0xff4a5a70),
    surface = Color(0xfff8f9fc),
    background = Color(0xffffffff),
    error = Color(0xffb3261e),
)

private val darkScheme = darkColorScheme(
    primary = Color(0xff6aa9f5),
    onPrimary = Color(0xff08121f),
    secondary = Color(0xff9cc7fa),
    surface = Color(0xff10141c),
    background = Color(0xff0a0e14),
    error = Color(0xffef8079),
)

@Composable
fun KeyleaseTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(
        LocalKeyleaseColors provides if (darkTheme) DarkKeyleaseColors else LightKeyleaseColors,
    ) {
        MaterialTheme(
            colorScheme = if (darkTheme) darkScheme else lightScheme,
            content = content,
        )
    }
}

/** Touch-density spacing, matching the Flutter touch scale (1.18). */
object KeyleaseDimens {
    const val gutter = 18
    const val gutterSmall = 10
    const val markSize = 44
    const val largeMarkSize = 64
    const val markRadius = 9
}
