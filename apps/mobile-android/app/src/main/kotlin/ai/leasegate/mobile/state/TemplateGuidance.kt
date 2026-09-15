package ai.leasegate.mobile.state

/** Per-template copy shown under the kind picker — port of `template_guidance.dart`. */
data class TemplateGuidance(val summary: String, val useWhen: String)

val templateGuidance: Map<String, TemplateGuidance> = mapOf(
    "core.prompt" to TemplateGuidance(
        summary = "Reusable instructions and context for an agent.",
        useWhen = "Use for tasks you repeat with the same rules or output format.",
    ),
    "core.runbook" to TemplateGuidance(
        summary = "An ordered operational procedure that an agent can follow.",
        useWhen = "Use for deploys, incidents, backups, recovery, and maintenance.",
    ),
    "core.environment" to TemplateGuidance(
        summary = "Environment variables and secrets for one project and stage.",
        useWhen = "Use for .env files, CI/CD secrets, containers, or Kubernetes.",
    ),
    "core.ssh_server" to TemplateGuidance(
        summary = "A complete SSH topology with hosts, bastions, sudo, and tunnels.",
        useWhen = "Use when one system needs direct or multi-hop SSH access.",
    ),
    "core.login" to TemplateGuidance(
        summary = "A website or app sign-in with password and optional one-time code.",
        useWhen = "Use for accounts you sign in to interactively.",
    ),
    "core.api_credential" to TemplateGuidance(
        summary = "API keys, tokens, client IDs, and client secrets for a service.",
        useWhen = "Use for programmatic access to an API or cloud provider.",
    ),
    "core.database" to TemplateGuidance(
        summary = "Database connection details, credentials, and connection string.",
        useWhen = "Use for an application database or an operator connection.",
    ),
    "core.ssh_key" to TemplateGuidance(
        summary = "An SSH key pair, fingerprint, and optional passphrase.",
        useWhen = "Use to archive or share the key material itself.",
    ),
    "core.secure_note" to TemplateGuidance(
        summary = "Free-form sensitive information protected as Markdown.",
        useWhen = "Use when structured fields do not fit the secret you need to keep.",
    ),
    "core.note" to TemplateGuidance(
        summary = "Reusable Markdown knowledge that an agent can read.",
        useWhen = "Use for project context, conventions, references, or decisions.",
    ),
    "core.password" to TemplateGuidance(
        summary = "A standalone password with an optional related website.",
        useWhen = "Use when there is no username or full login account to store.",
    ),
    "core.email_account" to TemplateGuidance(
        summary = "Email credentials and incoming or outgoing server settings.",
        useWhen = "Use for mailbox access, IMAP, POP, or SMTP configuration.",
    ),
    "core.server" to TemplateGuidance(
        summary = "Generic server facts and credentials without SSH topology.",
        useWhen = "Use for inventory or non-SSH access; prefer SSH Server for SSH.",
    ),
    "core.software_license" to TemplateGuidance(
        summary = "Software license keys, ownership, version, and purchase details.",
        useWhen = "Use for paid desktop, server, or developer software licenses.",
    ),
    "core.wireless_router" to TemplateGuidance(
        summary = "Router administration and Wi-Fi network credentials.",
        useWhen = "Use for a home, office, or temporary wireless network.",
    ),
    "core.credit_card" to TemplateGuidance(
        summary = "Payment card number, expiry, verification code, and PIN.",
        useWhen = "Use for a physical or virtual payment card.",
    ),
    "core.document" to TemplateGuidance(
        summary = "A general document number, issuer, and expiry date.",
        useWhen = "Use when no dedicated identity-document template applies.",
    ),
    "core.identity" to TemplateGuidance(
        summary = "A person or organization profile with contact information.",
        useWhen = "Use for reusable identity and form-filling details.",
    ),
    "core.bank_account" to TemplateGuidance(
        summary = "Bank account ownership, routing, IBAN, SWIFT, and PIN details.",
        useWhen = "Use for receiving payments or managing a bank account.",
    ),
    "core.crypto_wallet" to TemplateGuidance(
        summary = "A wallet address with private key, recovery phrase, and PIN.",
        useWhen = "Use for cryptocurrency or blockchain wallet recovery data.",
    ),
    "core.driver_license" to TemplateGuidance(
        summary = "Driver license identity, number, issuer, and validity dates.",
        useWhen = "Use for a driving credential issued by an authority.",
    ),
    "core.medical_record" to TemplateGuidance(
        summary = "Important patient, physician, insurance, and medication details.",
        useWhen = "Use for concise emergency or personal medical information.",
    ),
    "core.membership" to TemplateGuidance(
        summary = "Membership identifiers, organization, and validity details.",
        useWhen = "Use for clubs, associations, subscriptions, or access cards.",
    ),
    "core.outdoor_license" to TemplateGuidance(
        summary = "A hunting, fishing, boating, or other outdoor license.",
        useWhen = "Use for regulated activity permits and their expiry dates.",
    ),
    "core.passport" to TemplateGuidance(
        summary = "Passport identity, document number, issuer, and validity.",
        useWhen = "Use for international identity and travel details.",
    ),
    "core.reward_program" to TemplateGuidance(
        summary = "Loyalty program membership and account identifiers.",
        useWhen = "Use for airline, hotel, retail, or other rewards accounts.",
    ),
    "core.social_security_number" to TemplateGuidance(
        summary = "A protected government identity number and holder name.",
        useWhen = "Use for a Social Security Number or equivalent national ID.",
    ),
    "core.generic" to TemplateGuidance(
        summary = "A flexible item for information that has no dedicated template.",
        useWhen = "Use only when a more specific template does not fit.",
    ),
)

fun guidanceForTemplate(kind: String, label: String? = null): TemplateGuidance =
    templateGuidance[kind] ?: TemplateGuidance(
        summary = "Structured information for ${label ?: "this item type"}.",
        useWhen = "Use when this template matches the information you need to keep.",
    )
