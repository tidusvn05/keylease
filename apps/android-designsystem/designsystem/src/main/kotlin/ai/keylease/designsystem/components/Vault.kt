package ai.keylease.designsystem.components

import ai.keylease.designsystem.KeyleaseRadius
import ai.keylease.designsystem.KeyleaseSize
import ai.keylease.designsystem.KeyleaseSpacing
import ai.keylease.designsystem.KeyleaseTheme
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowDropDown
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

/** A revealed secret hides itself after this long. */
const val REVEAL_TIMEOUT_MILLIS = 15_000L

/**
 * A protected value with reveal, hide and copy. It only decides whether an
 * already fetched value is on screen; fetching, copying (sensitive clip,
 * cleared after 30 s) and `FLAG_SECURE` belong to the caller.
 *
 * @param revealed the value while shown, else null.
 * @param busy true while the reveal request runs.
 */
@Composable
fun SecretField(
    label: String,
    revealed: String?,
    hasValue: Boolean,
    onReveal: () -> Unit,
    onHide: () -> Unit,
    onCopy: () -> Unit,
    modifier: Modifier = Modifier,
    busy: Boolean = false,
) {
    val colors = KeyleaseTheme.colors
    if (revealed != null) {
        LaunchedEffect(revealed) {
            delay(REVEAL_TIMEOUT_MILLIS)
            onHide()
        }
    }
    Column(modifier.padding(vertical = KeyleaseSpacing.space6)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = colors.onSurfaceVariant)
        Spacer(Modifier.height(KeyleaseSpacing.space4))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = when {
                    revealed != null -> revealed
                    hasValue -> "••••••••"
                    else -> "Not set"
                },
                modifier = Modifier
                    .weight(1f)
                    .semantics {
                        if (revealed == null && hasValue) contentDescription = "$label hidden"
                    },
                style = if (revealed != null) KeyleaseTheme.text.monoMedium else MaterialTheme.typography.bodyMedium,
                color = if (hasValue) colors.ink else colors.onSurfaceVariant,
            )
            if (hasValue) {
                if (revealed == null) {
                    IconButton(onClick = onReveal, enabled = !busy) {
                        Icon(Icons.Rounded.Visibility, contentDescription = "Reveal $label")
                    }
                } else {
                    IconButton(onClick = onHide) {
                        Icon(Icons.Rounded.VisibilityOff, contentDescription = "Hide $label")
                    }
                }
                IconButton(onClick = onCopy, enabled = !busy) {
                    Icon(Icons.Rounded.ContentCopy, contentDescription = "Copy $label")
                }
            }
        }
    }
}

/**
 * The item's two-letter tile where a site icon would go. Never a key or
 * padlock glyph instead.
 *
 * @param text two letters from the item title.
 * @param size [KeyleaseSize.mark] in rows, [KeyleaseSize.markLarge] in a detail header.
 * @param standalone true where no title sits beside it: the letters then use
 *   `primary`, since `markForeground` is only 3.8:1 in light theme.
 */
@Composable
fun Monogram(
    text: String,
    modifier: Modifier = Modifier,
    size: Dp = KeyleaseSize.mark,
    standalone: Boolean = false,
) {
    val colors = KeyleaseTheme.colors
    Surface(
        modifier = modifier.size(size),
        shape = RoundedCornerShape(KeyleaseRadius.mark),
        color = colors.markSurface,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text.take(2).uppercase(),
                style = if (size >= KeyleaseSize.markLarge) MaterialTheme.typography.titleMedium
                else MaterialTheme.typography.titleSmall,
                color = if (standalone) colors.primary else colors.markForeground,
            )
        }
    }
}

/**
 * The small uppercase heading that starts a group. Pass sentence case.
 *
 * @param inset false inside a card, which already pads its content.
 */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier, inset: Boolean = true) {
    Text(
        text.uppercase(),
        modifier = modifier
            .padding(
                start = if (inset) KeyleaseSpacing.space16 else 0.dp,
                top = KeyleaseSpacing.gutter,
                bottom = KeyleaseSpacing.space6,
            )
            .semantics { contentDescription = text },
        style = MaterialTheme.typography.labelSmall,
        color = KeyleaseTheme.colors.onSurfaceVariant,
    )
}

/**
 * A read-only field that shows the chosen value and opens a picker
 * (a dialog or bottom sheet the caller owns) on tap.
 *
 * @param valueLabel the chosen option's label, or null for none.
 * @param error how to fix the problem, shown below in `danger`.
 */
@Composable
fun SelectField(
    label: String,
    valueLabel: String?,
    onOpen: () -> Unit,
    modifier: Modifier = Modifier,
    hint: String = "Choose",
    error: String? = null,
    enabled: Boolean = true,
) {
    val colors = KeyleaseTheme.colors
    Column(modifier) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = colors.onSurfaceVariant)
        Spacer(Modifier.height(KeyleaseSpacing.space4))
        Surface(
            onClick = onOpen,
            enabled = enabled,
            shape = RoundedCornerShape(KeyleaseRadius.field),
            color = colors.background,
            border = BorderStroke(1.dp, if (error != null) colors.danger else colors.outline),
            modifier = Modifier
                .fillMaxWidth()
                .semantics { role = Role.DropdownList },
        ) {
            Row(
                Modifier.padding(start = 14.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    valueLabel ?: hint,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (valueLabel != null) colors.ink else colors.onSurfaceVariant,
                )
                Icon(Icons.Rounded.ArrowDropDown, contentDescription = null, tint = colors.onSurfaceVariant)
            }
        }
        if (error != null) {
            Text(
                error,
                modifier = Modifier.padding(top = KeyleaseSpacing.space4),
                style = MaterialTheme.typography.bodySmall,
                color = colors.danger,
            )
        }
    }
}
