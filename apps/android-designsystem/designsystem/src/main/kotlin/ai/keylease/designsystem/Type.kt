package ai.keylease.designsystem

import androidx.compose.material3.Typography
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Secrets, TOTP codes, digests, fingerprints, commands and `kl://` references.
 *
 * The design system names JetBrains Mono. To bundle it, put
 * `jetbrains_mono_regular.ttf` (OFL) in `res/font/` of this module and replace
 * this with `FontFamily(Font(R.font.jetbrains_mono_regular))`. Until then the
 * platform monospace face is used.
 */
val KeyleaseMonoFamily: FontFamily = FontFamily.Monospace

/**
 * The Material 3 type scale in system Roboto, with the weights the app uses
 * where it departs from the defaults. Sizes are `sp`, so the user's font
 * scale applies.
 */
val KeyleaseTypography: Typography = Typography().let { base ->
    base.copy(
        // One per state screen: "Vault locked".
        headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        // Monogram letters, dense headings.
        titleSmall = base.titleSmall.copy(fontWeight = FontWeight.SemiBold),
        // Section labels; uppercase at the call site (SectionLabel).
        labelSmall = base.labelSmall.copy(fontWeight = FontWeight.SemiBold),
    )
}

/** Text styles outside the Material scale. */
@Immutable
data class KeyleaseTextStyles(
    /** Revealed secrets, TOTP codes, commands, identifiers. 14/20. */
    val monoMedium: TextStyle,
    /** Request digests, fingerprints, member ids. 12/16. */
    val monoSmall: TextStyle,
)

val DefaultKeyleaseTextStyles = KeyleaseTextStyles(
    monoMedium = TextStyle(fontFamily = KeyleaseMonoFamily, fontSize = 14.sp, lineHeight = 20.sp),
    monoSmall = TextStyle(fontFamily = KeyleaseMonoFamily, fontSize = 12.sp, lineHeight = 16.sp),
)

val LocalKeyleaseTextStyles = staticCompositionLocalOf { DefaultKeyleaseTextStyles }
