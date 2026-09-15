package ai.leasegate.mobile.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Star
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import ai.leasegate.mobile.core.UserMessage

/**
 * Full-screen phase/error state — the port of `StateScreen`: icon, headline,
 * explanation, optional actions, optional diagnostics disclosure.
 */
@Composable
fun StateScreen(
    title: String,
    message: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    footnote: String? = null,
    details: String? = null,
    actions: (@Composable () -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        if (icon != null) {
            Icon(
                icon,
                contentDescription = null,
                modifier = Modifier.size(56.dp),
                tint = LocalKeyleaseColors.current.accent,
            )
            Spacer(Modifier.height(18.dp))
        }
        Text(
            title,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        if (actions != null) {
            Spacer(Modifier.height(22.dp))
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) { actions() }
        }
        if (!details.isNullOrEmpty()) {
            Spacer(Modifier.height(18.dp))
            SelectionContainer {
                Text(
                    details,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
        if (footnote != null) {
            Spacer(Modifier.height(18.dp))
            Text(
                footnote,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** Dismissible message banner — the port of `MessageBanner`. */
@Composable
fun MessageBanner(
    message: UserMessage,
    modifier: Modifier = Modifier,
    onAction: (() -> Unit)? = null,
    onDismiss: (() -> Unit)? = null,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.35f),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    message.title,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    message.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (message.actionLabel != null && onAction != null) {
                    TextButton(onClick = onAction) { Text(message.actionLabel) }
                }
            }
            if (onDismiss != null) {
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Filled.Close, contentDescription = "Dismiss")
                }
            }
        }
    }
}

/**
 * The rounded brand monogram — the port of `KeyLeaseMark`/`EntryRow`'s mark.
 */
@Composable
fun KeyleaseMark(
    text: String,
    modifier: Modifier = Modifier,
    size: Int = KeyleaseDimens.markSize,
) {
    Surface(
        modifier = modifier.size(size.dp),
        shape = RoundedCornerShape(KeyleaseDimens.markRadius.dp),
        color = LocalKeyleaseColors.current.markSurface,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text,
                style = MaterialTheme.typography.titleSmall,
                color = LocalKeyleaseColors.current.markForeground,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}

/** Small caps section label — the port of `SectionLabel`. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        modifier = modifier.padding(start = 16.dp, top = 18.dp, bottom = 6.dp),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        fontWeight = FontWeight.SemiBold,
    )
}

/**
 * A protected value with reveal/hide/copy controls — the port of
 * `SecretField`. The value arrives already fetched; this widget only
 * decides whether it is on screen.
 */
@Composable
fun SecretField(
    label: String,
    revealed: String?,
    hasValue: Boolean,
    onReveal: () -> Unit,
    onHide: () -> Unit,
    onCopy: () -> Unit,
    busy: Boolean = false,
    modifier: Modifier = Modifier,
) {
    Column(modifier.padding(vertical = 6.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                when {
                    revealed != null -> revealed
                    hasValue -> "••••••••"
                    else -> "Not set"
                },
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (hasValue) {
                if (revealed == null) {
                    IconButton(onClick = onReveal, enabled = !busy) {
                        Icon(Icons.Filled.Visibility, contentDescription = "Reveal $label")
                    }
                } else {
                    IconButton(onClick = onHide) {
                        Icon(Icons.Filled.VisibilityOff, contentDescription = "Hide $label")
                    }
                }
                IconButton(onClick = onCopy, enabled = !busy) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy $label")
                }
            }
        }
    }
}

@Composable
fun KeyleaseButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    outline: Boolean = false,
    icon: ImageVector? = null,
) {
    val content: @Composable () -> Unit = {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.size(ButtonDefaults.IconSpacing))
        }
        Text(text)
    }
    if (outline) {
        OutlinedButton(onClick, modifier = modifier, enabled = enabled) { content() }
    } else {
        Button(onClick, modifier = modifier, enabled = enabled) { content() }
    }
}

@Composable
fun FavoriteToggle(favorite: Boolean, onToggle: () -> Unit, modifier: Modifier = Modifier) {
    IconButton(onClick = onToggle, modifier = modifier) {
        Icon(
            if (favorite) Icons.Filled.Star else Icons.Outlined.Star,
            contentDescription = if (favorite) "Remove from favorites" else "Add to favorites",
            tint = if (favorite) {
                LocalKeyleaseColors.current.warning
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
    }
}

@Composable
fun LoadingSpinner(modifier: Modifier = Modifier) {
    Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

/** One option in a [SearchableSelectField] / [SelectField]. */
data class SelectOption<T>(
    val value: T,
    val label: String,
    val subtitle: String? = null,
    val section: String? = null,
    val searchTerms: List<String> = emptyList(),
)

/**
 * The port of `SearchableSelect`: a read-only field that opens a dialog with
 * a search box and the (sectioned) options. Selection returns the value.
 */
@Composable
fun <T> SearchableSelectField(
    label: String,
    options: List<SelectOption<T>>,
    value: T?,
    onChange: (T?) -> Unit,
    modifier: Modifier = Modifier,
    hint: String = "Choose",
    error: String? = null,
    enabled: Boolean = true,
) {
    var open by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    val selected = options.firstOrNull { it.value == value }

    Column(modifier) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Surface(
            onClick = { if (enabled) open = true },
            shape = RoundedCornerShape(8.dp),
            border = BorderStroke(
                1.dp,
                if (error != null) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.outline,
            ),
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    selected?.label ?: hint,
                    modifier = Modifier.weight(1f),
                    color = if (selected == null) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    },
                )
                Icon(
                    Icons.Filled.KeyboardArrowDown,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (error != null) {
            Text(
                error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(top = 4.dp, start = 4.dp),
            )
        }
    }

    if (open) {
        val filtered = options.filter { option ->
            query.isBlank() ||
                option.label.contains(query, ignoreCase = true) ||
                option.searchTerms.any { it.contains(query, ignoreCase = true) }
        }
        AlertDialog(
            onDismissRequest = { open = false; query = "" },
            title = { Text(label) },
            text = {
                Column {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        placeholder = { Text("Search") },
                        leadingIcon = { Icon(Icons.Filled.Search, null) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    LazyColumn(Modifier.heightIn(max = 380.dp)) {
                        var lastSection: String? = null
                        for (option in filtered) {
                            if (option.section != lastSection) {
                                lastSection = option.section
                                if (lastSection != null) {
                                    item(key = "section:$lastSection") {
                                        Text(
                                            lastSection!!.uppercase(),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                                        )
                                    }
                                }
                            }
                            item(key = option.label + option.value.toString()) {
                                ListItem(
                                    modifier = Modifier.clickable {
                                        onChange(option.value)
                                        open = false
                                        query = ""
                                    },
                                    headlineContent = { Text(option.label) },
                                    supportingContent = option.subtitle?.let { { Text(it) } },
                                    trailingContent = {
                                        if (option.value == value) {
                                            Icon(Icons.Filled.Check, contentDescription = null)
                                        }
                                    },
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { open = false; query = "" }) { Text("Cancel") }
            },
        )
    }
}

/** Simple fixed-list dropdown — the port of `FSelect`. */
@Composable
fun <T> SelectField(
    label: String,
    items: List<Pair<String, T>>,
    value: T,
    onChange: (T) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    SearchableSelectField(
        label = label,
        options = items.map { (itemLabel, itemValue) ->
            SelectOption(value = itemValue, label = itemLabel)
        },
        value = value,
        onChange = { next -> if (next != null) onChange(next) },
        modifier = modifier,
        enabled = enabled,
    )
}
