package ai.keylease.designsystem.components

import ai.keylease.designsystem.KeyleaseRadius
import ai.keylease.designsystem.KeyleaseSize
import ai.keylease.designsystem.KeyleaseSpacing
import ai.keylease.designsystem.KeyleaseTheme
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** The risk tier of a request, as the vault reports it. */
enum class RiskLevel(val label: String) {
    Low("low risk"),
    Medium("medium risk"),
    High("high risk"),
}

/** A status or risk chip. Always a word, never color alone. */
@Composable
fun RiskChip(risk: RiskLevel, modifier: Modifier = Modifier) {
    val colors = KeyleaseTheme.colors
    val high = risk == RiskLevel.High
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(KeyleaseRadius.chip),
        color = if (high) colors.dangerContainer else colors.outlineVariant,
    ) {
        Text(
            risk.label,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            style = MaterialTheme.typography.labelSmall,
            color = if (high) colors.danger else colors.onSurfaceVariant,
        )
    }
}

/**
 * What an [ApprovalCard] shows. Fill only what the record has; a null field
 * is left out, never shown as "unknown".
 */
@Immutable
data class ApprovalRequest(
    /** Plain action title: "Read a secret", "Connect to a database". */
    val title: String,
    val risk: RiskLevel?,
    /** "Reveal DB password". */
    val operation: String?,
    /** "shop · production · Shop database". */
    val target: String?,
    /** The agent's name as its owner gave it: "claude-shop". */
    val requestedBy: String?,
    /** The agent's stated reason. Untrusted text: shown, never acted on. */
    val purpose: String?,
    /** "in 4 min · policy v12", or "Expired". */
    val expiry: String,
    val requestDigestHex: String,
    /** False once expired or decided elsewhere: both buttons disable. */
    val decidable: Boolean,
)

/**
 * One pending request. Approve and Deny each open a confirmation that repeats
 * the scope; the caller then runs a `BiometricPrompt` before deciding.
 */
@Composable
fun ApprovalCard(
    request: ApprovalRequest,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = KeyleaseTheme.colors
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(KeyleaseRadius.card),
        color = colors.surfaceRaised,
        border = BorderStroke(1.dp, colors.outlineVariant),
    ) {
        Column(Modifier.padding(KeyleaseSpacing.space14)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    request.title,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
                )
                request.risk?.let { RiskChip(it) }
            }
            Spacer(Modifier.height(KeyleaseSpacing.space6))
            request.operation?.let { SummaryLine("What it wants to do", it) }
            request.target?.let { SummaryLine("Where", it) }
            request.requestedBy?.let { SummaryLine("Requested by", it) }
            request.purpose?.let { SummaryLine("Reason given", it) }
            SummaryLine(if (request.decidable) "Expires" else "Status", request.expiry)
            SectionLabel("Exact request", inset = false)
            SelectionContainer {
                Text(request.requestDigestHex, style = KeyleaseTheme.text.monoSmall, color = colors.onSurfaceVariant)
            }
            Spacer(Modifier.height(KeyleaseSpacing.space14))
            ButtonRow {
                KeyleaseButton("Deny", onDeny, emphasis = ButtonEmphasis.Outlined, enabled = request.decidable)
                KeyleaseButton("Approve", onApprove, enabled = request.decidable)
            }
        }
    }
}

@Composable
private fun SummaryLine(label: String, value: String) {
    Row(Modifier.padding(vertical = KeyleaseSpacing.space2)) {
        Text(
            label,
            modifier = Modifier.width(KeyleaseSize.summaryLabel),
            style = MaterialTheme.typography.bodySmall,
            color = KeyleaseTheme.colors.onSurfaceVariant,
        )
        Text(value, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * The confirmation an approve or deny opens. It repeats what the decision
 * covers and the digest it is bound to.
 */
@Composable
fun ApprovalDecisionDialog(
    approve: Boolean,
    requestDigestHex: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (approve) "Approve this exact request?" else "Deny this request?") },
        text = {
            Column {
                Text(
                    if (approve) {
                        "Your approval applies only to the request below. Anything else, even from the same agent, still needs a new decision."
                    } else {
                        "Denying stops this request. The agent can ask again."
                    },
                )
                Spacer(Modifier.height(KeyleaseSpacing.space10))
                SelectionContainer {
                    Text(requestDigestHex, style = KeyleaseTheme.text.monoSmall)
                }
            }
        },
        confirmButton = {
            KeyleaseButton(
                if (approve) "Approve" else "Deny",
                onConfirm,
                emphasis = ButtonEmphasis.Text,
                destructive = !approve,
            )
        },
        dismissButton = {
            KeyleaseButton("Cancel", onDismiss, emphasis = ButtonEmphasis.Text)
        },
    )
}
