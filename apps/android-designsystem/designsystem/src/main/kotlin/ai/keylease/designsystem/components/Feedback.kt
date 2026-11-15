package ai.keylease.designsystem.components

import ai.keylease.designsystem.KeyleaseSize
import ai.keylease.designsystem.KeyleaseSpacing
import ai.keylease.designsystem.KeyleaseTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/** What a [MessageBanner] reports. */
enum class BannerTone { Error, Info }

/**
 * A full-width message under the app bar: what happened, then how to fix it.
 * One per screen. For a transient confirmation ("Copied. Clears in 30
 * seconds.") use a Material Snackbar instead.
 *
 * @param diagnostics an error code or id, shown selectable in mono; never in the title.
 */
@Composable
fun MessageBanner(
    title: String,
    modifier: Modifier = Modifier,
    detail: String? = null,
    tone: BannerTone = BannerTone.Error,
    diagnostics: String? = null,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
    onDismiss: (() -> Unit)? = null,
) {
    val colors = KeyleaseTheme.colors
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .semantics { liveRegion = LiveRegionMode.Polite },
        color = if (tone == BannerTone.Error) colors.dangerContainer else colors.markSurface,
        contentColor = colors.ink,
    ) {
        Row(
            modifier = Modifier.padding(
                start = KeyleaseSpacing.space16,
                top = KeyleaseSpacing.space10,
                bottom = KeyleaseSpacing.space10,
            ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                if (!detail.isNullOrEmpty()) {
                    Text(detail, style = MaterialTheme.typography.bodySmall, color = colors.onSurfaceVariant)
                }
                if (!diagnostics.isNullOrEmpty()) {
                    SelectionContainer {
                        Text(diagnostics, style = KeyleaseTheme.text.monoSmall, color = colors.onSurfaceVariant)
                    }
                }
                if (actionLabel != null && onAction != null) {
                    KeyleaseButton(actionLabel, onAction, emphasis = ButtonEmphasis.Text)
                }
            }
            if (onDismiss != null) {
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Rounded.Close, contentDescription = "Dismiss")
                }
            } else {
                Spacer(Modifier.size(KeyleaseSpacing.space16))
            }
        }
    }
}

/**
 * A full screen for a phase or an empty list: icon, one headline, one
 * explanation, the way forward. Titles are states ("Vault locked",
 * "No approvals waiting"), not apologies.
 *
 * @param actions one filled [KeyleaseButton], optionally one text button below it.
 */
@Composable
fun StateScreen(
    title: String,
    message: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    details: String? = null,
    footnote: String? = null,
    actions: (@Composable () -> Unit)? = null,
) {
    val colors = KeyleaseTheme.colors
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = KeyleaseSpacing.space28, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(KeyleaseSize.stateIcon), tint = colors.primary)
            Spacer(Modifier.height(KeyleaseSpacing.gutter))
        }
        Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        Spacer(Modifier.height(KeyleaseSpacing.space10))
        Text(
            message,
            style = MaterialTheme.typography.bodyMedium,
            color = colors.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        if (actions != null) {
            Spacer(Modifier.height(KeyleaseSpacing.space22))
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(KeyleaseSpacing.space10),
            ) { actions() }
        }
        if (!details.isNullOrEmpty()) {
            Spacer(Modifier.height(KeyleaseSpacing.gutter))
            SelectionContainer {
                Text(details, style = KeyleaseTheme.text.monoSmall, color = colors.onSurfaceVariant, textAlign = TextAlign.Center)
            }
        }
        if (footnote != null) {
            Spacer(Modifier.height(KeyleaseSpacing.gutter))
            Text(footnote, style = MaterialTheme.typography.bodySmall, color = colors.onSurfaceVariant, textAlign = TextAlign.Center)
        }
    }
}
