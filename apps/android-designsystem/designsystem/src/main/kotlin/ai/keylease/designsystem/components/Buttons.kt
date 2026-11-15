package ai.keylease.designsystem.components

import ai.keylease.designsystem.KeyleaseTheme
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.StarOutline
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp

/** How much a [KeyleaseButton] asks for attention. */
enum class ButtonEmphasis {
    /** The one action the view wants taken. One per view. */
    Filled,

    /** The alternative to the filled action (Deny next to Approve). */
    Outlined,

    /** Low emphasis, and dialog actions. */
    Text,
}

/**
 * The control for an action. Name it with a verb and its scope
 * ("Allow once", "Copy password"), never "OK" or "Continue".
 *
 * @param destructive colors a [ButtonEmphasis.Text] or [ButtonEmphasis.Outlined]
 *   button with `danger` ("Delete item"). A destructive action is never filled.
 */
@Composable
fun KeyleaseButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    emphasis: ButtonEmphasis = ButtonEmphasis.Filled,
    enabled: Boolean = true,
    destructive: Boolean = false,
    icon: ImageVector? = null,
) {
    val colors = KeyleaseTheme.colors
    val content: @Composable RowScope.() -> Unit = {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.size(ButtonDefaults.IconSpacing))
        }
        Text(text, style = MaterialTheme.typography.labelLarge)
    }
    when (emphasis) {
        ButtonEmphasis.Filled -> Button(
            onClick = onClick,
            modifier = modifier,
            enabled = enabled,
            colors = ButtonDefaults.buttonColors(
                containerColor = colors.primary,
                contentColor = colors.onPrimary,
            ),
            content = content,
        )
        ButtonEmphasis.Outlined -> OutlinedButton(
            onClick = onClick,
            modifier = modifier,
            enabled = enabled,
            border = BorderStroke(1.dp, colors.outline),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = if (destructive) colors.danger else colors.primary,
            ),
            content = content,
        )
        ButtonEmphasis.Text -> TextButton(
            onClick = onClick,
            modifier = modifier,
            enabled = enabled,
            colors = ButtonDefaults.textButtonColors(
                contentColor = if (destructive) colors.danger else colors.primary,
            ),
            content = content,
        )
    }
}

/**
 * A row of actions: right-aligned, 10dp apart. Put the filled action last.
 */
@Composable
fun ButtonRow(modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp, Alignment.End),
        content = content,
    )
}

/** The star that pins an item to Favorites. Its label states the result. */
@Composable
fun FavoriteToggle(favorite: Boolean, onToggle: () -> Unit, modifier: Modifier = Modifier) {
    IconButton(onClick = onToggle, modifier = modifier) {
        Icon(
            if (favorite) Icons.Rounded.Star else Icons.Rounded.StarOutline,
            contentDescription = if (favorite) "Remove from favorites" else "Add to favorites",
            tint = if (favorite) KeyleaseTheme.colors.warning else KeyleaseTheme.colors.onSurfaceVariant,
        )
    }
}
