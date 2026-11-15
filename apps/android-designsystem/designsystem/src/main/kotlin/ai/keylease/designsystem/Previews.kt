package ai.keylease.designsystem

import ai.keylease.designsystem.components.ApprovalCard
import ai.keylease.designsystem.components.ApprovalRequest
import ai.keylease.designsystem.components.BannerTone
import ai.keylease.designsystem.components.ButtonEmphasis
import ai.keylease.designsystem.components.ButtonRow
import ai.keylease.designsystem.components.FavoriteToggle
import ai.keylease.designsystem.components.KeyleaseButton
import ai.keylease.designsystem.components.MessageBanner
import ai.keylease.designsystem.components.Monogram
import ai.keylease.designsystem.components.RiskLevel
import ai.keylease.designsystem.components.SecretField
import ai.keylease.designsystem.components.SectionLabel
import ai.keylease.designsystem.components.SelectField
import ai.keylease.designsystem.components.StateScreen
import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview

/** Light and dark, for every gallery below. */
@Preview(name = "Light", showBackground = true, widthDp = 380)
@Preview(name = "Dark", showBackground = true, widthDp = 380, uiMode = Configuration.UI_MODE_NIGHT_YES)
annotation class KeyleasePreviews

@Composable
private fun Gallery(content: @Composable () -> Unit) {
    KeyleaseTheme {
        Surface(color = KeyleaseTheme.colors.background) {
            Column(
                Modifier
                    .verticalScroll(rememberScrollState())
                    .padding(vertical = KeyleaseSpacing.space16),
                verticalArrangement = Arrangement.spacedBy(KeyleaseSpacing.space10),
            ) { content() }
        }
    }
}

private val sampleRequest = ApprovalRequest(
    title = "Read a secret",
    risk = RiskLevel.High,
    operation = "Reveal DB password",
    target = "shop · production · Shop database",
    requestedBy = "claude-shop",
    purpose = "Run the nightly migration",
    expiry = "in 4 min · policy v12",
    requestDigestHex = "9f2c4e1ab07d53e8c61f0a9b2d7e44c18a3f5b6c9d0e1f2a3b4c5d6e7f8091a2",
    decidable = true,
)

@KeyleasePreviews
@Composable
private fun ButtonsPreview() = Gallery {
    Row(
        Modifier.padding(horizontal = KeyleaseSpacing.gutter),
        horizontalArrangement = Arrangement.spacedBy(KeyleaseSpacing.space10),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        KeyleaseButton("Approve", {})
        KeyleaseButton("Deny", {}, emphasis = ButtonEmphasis.Outlined)
        FavoriteToggle(favorite = true, onToggle = {})
    }
    ButtonRow(Modifier.padding(horizontal = KeyleaseSpacing.gutter)) {
        KeyleaseButton("Delete item", {}, emphasis = ButtonEmphasis.Text, destructive = true)
        KeyleaseButton("Lock vault", {}, icon = Icons.Rounded.Lock)
    }
}

@KeyleasePreviews
@Composable
private fun BannersPreview() = Gallery {
    MessageBanner(
        title = "Could not reach the vault",
        detail = "The KeyLease service did not answer in 30 seconds.",
        diagnostics = "SERVICE_UNAVAILABLE",
        onDismiss = {},
    )
    MessageBanner(
        title = "Console approvals are on",
        detail = "Requests from this phone also appear in the KeyLease Console.",
        tone = BannerTone.Info,
        onDismiss = {},
    )
}

@KeyleasePreviews
@Composable
private fun VaultPreview() = Gallery {
    SectionLabel("Login")
    Row(
        Modifier.padding(horizontal = KeyleaseSpacing.space16),
        horizontalArrangement = Arrangement.spacedBy(KeyleaseSpacing.space14),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Monogram("GH")
        Column {
            Text("GitHub")
            Text("deploy-bot", color = KeyleaseTheme.colors.onSurfaceVariant)
        }
    }
    Column(Modifier.padding(horizontal = KeyleaseSpacing.space16)) {
        SecretField("Password", revealed = null, hasValue = true, onReveal = {}, onHide = {}, onCopy = {})
        SecretField("API token", revealed = "ghp_8kD2mQ7vXa41LsT9", hasValue = true, onReveal = {}, onHide = {}, onCopy = {})
        SelectField("Project", valueLabel = null, onOpen = {}, error = "Choose a project for this item.")
    }
}

@KeyleasePreviews
@Composable
private fun ApprovalPreview() = Gallery {
    ApprovalCard(
        sampleRequest,
        onApprove = {},
        onDeny = {},
        modifier = Modifier.padding(horizontal = KeyleaseSpacing.gutter),
    )
}

@Preview(name = "State screen", showBackground = true, widthDp = 380, heightDp = 520)
@Composable
private fun StateScreenPreview() = KeyleaseTheme {
    Surface(color = KeyleaseTheme.colors.background) {
        StateScreen(
            title = "Vault locked",
            message = "Unlock your vault to access your items.",
            icon = Icons.Rounded.Lock,
        ) {
            KeyleaseButton("Unlock with fingerprint", {})
            KeyleaseButton("Use master password", {}, emphasis = ButtonEmphasis.Text)
        }
    }
}
