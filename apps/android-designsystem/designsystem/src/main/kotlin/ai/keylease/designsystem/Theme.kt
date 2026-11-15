package ai.keylease.designsystem

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable

/**
 * The KeyLease theme. Wrap the whole app in it:
 *
 * ```kotlin
 * setContent { KeyleaseTheme { App() } }
 * ```
 *
 * Material components pick up the roles through [MaterialTheme]; KeyLease
 * roles Material has no slot for (success, warning, mark…) are read with
 * `KeyleaseTheme.colors`. Dynamic color (Material You) is deliberately not
 * offered: the vault keeps its own look so a spoofed screen is easier to spot.
 */
@Composable
fun KeyleaseTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) DarkKeyleaseColors else LightKeyleaseColors
    CompositionLocalProvider(
        LocalKeyleaseColors provides colors,
        LocalKeyleaseTextStyles provides DefaultKeyleaseTextStyles,
    ) {
        MaterialTheme(
            colorScheme = colors.toColorScheme(darkTheme),
            typography = KeyleaseTypography,
            shapes = KeyleaseShapes,
            content = content,
        )
    }
}

/** Shorthand for the theme's values inside composables. */
object KeyleaseTheme {
    val colors: KeyleaseColors
        @Composable @ReadOnlyComposable
        get() = LocalKeyleaseColors.current

    val text: KeyleaseTextStyles
        @Composable @ReadOnlyComposable
        get() = LocalKeyleaseTextStyles.current
}

/**
 * Every Material slot set explicitly, so no component falls back to the
 * baseline purple. Containers Material tints by elevation all map to the
 * three KeyLease grounds: elevation is shown by borders, not tint.
 * `lightColorScheme` only supplies defaults for unset slots, and every slot
 * is set, so it serves both themes.
 */
fun KeyleaseColors.toColorScheme(dark: Boolean): ColorScheme = lightColorScheme(
    primary = primary,
    onPrimary = onPrimary,
    primaryContainer = markSurface,
    onPrimaryContainer = ink,
    inversePrimary = if (dark) LightKeyleaseColors.primary else DarkKeyleaseColors.primary,
    secondary = onSurfaceVariant,
    onSecondary = background,
    secondaryContainer = markSurface,
    onSecondaryContainer = ink,
    tertiary = success,
    onTertiary = background,
    tertiaryContainer = successContainer,
    onTertiaryContainer = ink,
    background = background,
    onBackground = ink,
    surface = surface,
    onSurface = ink,
    surfaceVariant = surface,
    onSurfaceVariant = onSurfaceVariant,
    surfaceTint = surface,
    inverseSurface = ink,
    inverseOnSurface = background,
    error = danger,
    onError = background,
    errorContainer = dangerContainer,
    onErrorContainer = ink,
    outline = outline,
    outlineVariant = outlineVariant,
    scrim = scrim,
    surfaceBright = surfaceRaised,
    surfaceContainer = surfaceRaised,
    surfaceContainerHigh = surfaceRaised,
    surfaceContainerHighest = surfaceRaised,
    surfaceContainerLow = surfaceRaised,
    surfaceContainerLowest = background,
    surfaceDim = surface,
)
