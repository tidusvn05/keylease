use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::Sensitivity;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemKindFamily {
    Common,
    Personal,
    Developer,
    AgentKnowledge,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemFieldDefinition {
    pub key: String,
    pub label: String,
    pub value_type: String,
    pub semantic_role: String,
    pub sensitivity: Sensitivity,
    pub protected: bool,
    pub section: String,
    pub aliases: Vec<String>,
    pub mask_last: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemKindDefinition {
    pub kind: String,
    pub template_version: u32,
    pub label: String,
    pub icon: String,
    pub family: ItemKindFamily,
    pub markdown_notes: bool,
    pub fields: Vec<ItemFieldDefinition>,
}

#[allow(clippy::too_many_arguments)]
fn field(
    key: &str,
    label: &str,
    value_type: &str,
    role: &str,
    sensitivity: Sensitivity,
    protected: bool,
    section: &str,
    aliases: &[&str],
) -> ItemFieldDefinition {
    ItemFieldDefinition {
        key: key.into(),
        label: label.into(),
        value_type: value_type.into(),
        semantic_role: role.into(),
        sensitivity,
        protected,
        section: section.into(),
        aliases: aliases.iter().map(|value| (*value).into()).collect(),
        mask_last: matches!(role, "card_number" | "account_number").then_some(4),
    }
}

fn kind(
    id: &str,
    label: &str,
    icon: &str,
    family: ItemKindFamily,
    markdown_notes: bool,
    fields: Vec<ItemFieldDefinition>,
) -> ItemKindDefinition {
    ItemKindDefinition {
        kind: format!("core.{id}"),
        template_version: 1,
        label: label.into(),
        icon: icon.into(),
        family,
        markdown_notes,
        fields,
    }
}

fn text(
    key: &str,
    label: &str,
    role: &str,
    section: &str,
    aliases: &[&str],
) -> ItemFieldDefinition {
    field(
        key,
        label,
        "text",
        role,
        Sensitivity::PrivateMetadata,
        false,
        section,
        aliases,
    )
}

fn secret(
    key: &str,
    label: &str,
    role: &str,
    section: &str,
    aliases: &[&str],
) -> ItemFieldDefinition {
    field(
        key,
        label,
        "concealed",
        role,
        Sensitivity::HighlySensitive,
        true,
        section,
        aliases,
    )
}

fn url(key: &str, label: &str, role: &str, section: &str, aliases: &[&str]) -> ItemFieldDefinition {
    field(
        key,
        label,
        "url",
        role,
        Sensitivity::PrivateMetadata,
        false,
        section,
        aliases,
    )
}

pub fn builtin_item_kinds() -> Vec<ItemKindDefinition> {
    use ItemKindFamily::{AgentKnowledge, Common, Developer, Other, Personal};
    vec![
        kind(
            "login",
            "Login",
            "login",
            Common,
            true,
            vec![
                text(
                    "username",
                    "Username",
                    "username",
                    "Login",
                    &["user", "login"],
                ),
                secret(
                    "password",
                    "Password",
                    "password",
                    "Login",
                    &["pass", "passwd"],
                ),
                url("website", "Website", "website", "Login", &["url", "site"]),
                field(
                    "otp",
                    "One-time password",
                    "totp",
                    "otp",
                    Sensitivity::Secret,
                    true,
                    "Login",
                    &["totp", "one time password"],
                ),
            ],
        ),
        kind(
            "secure_note",
            "Secure Note",
            "note-lock",
            Common,
            true,
            vec![],
        ),
        kind(
            "credit_card",
            "Credit Card",
            "credit-card",
            Common,
            true,
            vec![
                text(
                    "cardholder",
                    "Cardholder",
                    "cardholder",
                    "Card",
                    &["cardholder name", "name on card"],
                ),
                text(
                    "card_type",
                    "Card type",
                    "card_type",
                    "Card",
                    &["brand", "type"],
                ),
                secret(
                    "card_number",
                    "Card number",
                    "card_number",
                    "Card",
                    &[
                        "card number",
                        "credit card number",
                        "cc number",
                        "card no",
                        "number",
                    ],
                ),
                secret(
                    "verification_number",
                    "CVV",
                    "card_verification",
                    "Card",
                    &["cvv", "cvc", "security code", "verification number"],
                ),
                field(
                    "expiry",
                    "Expiry",
                    "month_year",
                    "card_expiry",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Card",
                    &["expiry date", "expiration"],
                ),
                field(
                    "valid_from",
                    "Valid from",
                    "month_year",
                    "card_valid_from",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Card",
                    &["valid from"],
                ),
                secret("pin", "PIN", "pin", "Card", &["pin"]),
                text(
                    "issuing_bank",
                    "Issuing bank",
                    "issuer",
                    "Details",
                    &["bank", "issuer"],
                ),
            ],
        ),
        kind(
            "identity",
            "Identity",
            "identity",
            Common,
            true,
            vec![
                text(
                    "first_name",
                    "First name",
                    "first_name",
                    "Name",
                    &["given name"],
                ),
                text("middle_name", "Middle name", "middle_name", "Name", &[]),
                text(
                    "last_name",
                    "Last name",
                    "last_name",
                    "Name",
                    &["surname", "family name"],
                ),
                field(
                    "birth_date",
                    "Birth date",
                    "date",
                    "birth_date",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Details",
                    &["date of birth", "dob"],
                ),
                text(
                    "company",
                    "Company",
                    "company",
                    "Details",
                    &["organization"],
                ),
                field(
                    "address",
                    "Address",
                    "address",
                    "address",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Contact",
                    &["home address"],
                ),
                field(
                    "email",
                    "Email",
                    "email",
                    "email",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Contact",
                    &["email address"],
                ),
                field(
                    "phone",
                    "Phone",
                    "phone",
                    "phone",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Contact",
                    &["telephone", "mobile"],
                ),
            ],
        ),
        kind(
            "password",
            "Password",
            "key",
            Common,
            true,
            vec![
                secret(
                    "password",
                    "Password",
                    "password",
                    "Password",
                    &["pass", "passwd"],
                ),
                url("website", "Website", "website", "Password", &["url"]),
            ],
        ),
        kind(
            "document",
            "Document",
            "document",
            Common,
            true,
            vec![
                text(
                    "document_type",
                    "Document type",
                    "document_type",
                    "Document",
                    &["type"],
                ),
                secret(
                    "document_number",
                    "Document number",
                    "document_number",
                    "Document",
                    &["number", "id number"],
                ),
                text(
                    "issuer",
                    "Issuer",
                    "issuer",
                    "Document",
                    &["issuing authority"],
                ),
                field(
                    "expiry",
                    "Expiry",
                    "date",
                    "expiry",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Document",
                    &["expiration"],
                ),
            ],
        ),
        kind(
            "bank_account",
            "Bank Account",
            "bank",
            Personal,
            true,
            vec![
                text("bank_name", "Bank", "bank", "Account", &["bank name"]),
                text(
                    "account_holder",
                    "Account holder",
                    "account_holder",
                    "Account",
                    &["name"],
                ),
                secret(
                    "account_number",
                    "Account number",
                    "account_number",
                    "Account",
                    &["account no"],
                ),
                secret(
                    "routing_number",
                    "Routing number",
                    "routing_number",
                    "Account",
                    &["routing", "sort code"],
                ),
                secret("iban", "IBAN", "iban", "Account", &["iban"]),
                secret(
                    "swift",
                    "SWIFT/BIC",
                    "swift",
                    "Account",
                    &["bic", "swift code"],
                ),
                secret("pin", "PIN", "pin", "Account", &["pin"]),
            ],
        ),
        kind(
            "crypto_wallet",
            "Crypto Wallet",
            "wallet",
            Personal,
            true,
            vec![
                text("network", "Network", "network", "Wallet", &["chain"]),
                text(
                    "address",
                    "Wallet address",
                    "wallet_address",
                    "Wallet",
                    &["public address"],
                ),
                secret(
                    "private_key",
                    "Private key",
                    "private_key",
                    "Secrets",
                    &["private key"],
                ),
                secret(
                    "recovery_phrase",
                    "Recovery phrase",
                    "recovery_phrase",
                    "Secrets",
                    &["seed phrase", "mnemonic"],
                ),
                secret("pin", "PIN", "pin", "Secrets", &["pin"]),
            ],
        ),
        kind(
            "driver_license",
            "Driver License",
            "license",
            Personal,
            true,
            identity_document_fields(),
        ),
        kind(
            "medical_record",
            "Medical Record",
            "medical",
            Personal,
            true,
            vec![
                text(
                    "patient_name",
                    "Patient",
                    "person_name",
                    "Patient",
                    &["name"],
                ),
                field(
                    "birth_date",
                    "Birth date",
                    "date",
                    "birth_date",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Patient",
                    &["dob"],
                ),
                text("blood_type", "Blood type", "blood_type", "Medical", &[]),
                text(
                    "physician",
                    "Physician",
                    "physician",
                    "Medical",
                    &["doctor"],
                ),
                secret(
                    "insurance_number",
                    "Insurance number",
                    "insurance_number",
                    "Insurance",
                    &["member id"],
                ),
                text("allergies", "Allergies", "allergies", "Medical", &[]),
                text("medications", "Medications", "medications", "Medical", &[]),
            ],
        ),
        kind(
            "membership",
            "Membership",
            "membership",
            Personal,
            true,
            membership_fields(),
        ),
        kind(
            "outdoor_license",
            "Outdoor License",
            "outdoor",
            Personal,
            true,
            identity_document_fields(),
        ),
        kind(
            "passport",
            "Passport",
            "passport",
            Personal,
            true,
            passport_fields(),
        ),
        kind(
            "reward_program",
            "Reward Program",
            "rewards",
            Personal,
            true,
            membership_fields(),
        ),
        kind(
            "social_security_number",
            "Social Security Number",
            "identity-number",
            Personal,
            true,
            vec![
                text("name", "Name", "person_name", "Identity", &["full name"]),
                secret(
                    "number",
                    "Number",
                    "identity_number",
                    "Identity",
                    &["ssn", "social security number"],
                ),
            ],
        ),
        kind(
            "api_credential",
            "API Credential",
            "api",
            Developer,
            true,
            vec![
                text(
                    "provider",
                    "Provider",
                    "provider",
                    "Credential",
                    &["service"],
                ),
                text(
                    "client_id",
                    "Client/Key ID",
                    "client_id",
                    "Credential",
                    &["key id", "api key id"],
                ),
                secret(
                    "credential",
                    "Credential",
                    "credential",
                    "Credential",
                    &["api key", "token"],
                ),
                secret(
                    "client_secret",
                    "Client secret",
                    "client_secret",
                    "Credential",
                    &["api secret", "secret"],
                ),
                url("hostname", "Host", "host", "Details", &["url", "website"]),
                field(
                    "expiry",
                    "Expiry",
                    "date",
                    "expiry",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Details",
                    &["expiration"],
                ),
            ],
        ),
        kind(
            "database",
            "Database",
            "database",
            Developer,
            true,
            vec![
                text(
                    "engine",
                    "Engine",
                    "database_engine",
                    "Connection",
                    &["type"],
                ),
                text(
                    "host",
                    "Host",
                    "host",
                    "Connection",
                    &["server", "hostname"],
                ),
                field(
                    "port",
                    "Port",
                    "number",
                    "port",
                    Sensitivity::PrivateMetadata,
                    false,
                    "Connection",
                    &[],
                ),
                text(
                    "database",
                    "Database",
                    "database_name",
                    "Connection",
                    &["dbname"],
                ),
                text("username", "Username", "username", "Credential", &["user"]),
                secret("password", "Password", "password", "Credential", &["pass"]),
                secret(
                    "connection_string",
                    "Connection string",
                    "connection_string",
                    "Credential",
                    &["dsn", "database url"],
                ),
            ],
        ),
        kind(
            "email_account",
            "Email Account",
            "email",
            Developer,
            true,
            email_fields(),
        ),
        kind(
            "ssh_key",
            "SSH Key",
            "ssh",
            Developer,
            true,
            vec![
                text("key_type", "Key type", "key_type", "Key", &["algorithm"]),
                text(
                    "public_key",
                    "Public key",
                    "public_key",
                    "Key",
                    &["ssh public key"],
                ),
                secret(
                    "private_key",
                    "Private key",
                    "private_key",
                    "Key",
                    &["ssh private key"],
                ),
                text(
                    "fingerprint",
                    "Fingerprint",
                    "fingerprint",
                    "Key",
                    &["sha256 fingerprint"],
                ),
                secret(
                    "passphrase",
                    "Passphrase",
                    "passphrase",
                    "Key",
                    &["password"],
                ),
                text("comment", "Comment", "comment", "Details", &[]),
            ],
        ),
        kind(
            "server",
            "Server",
            "server",
            Developer,
            true,
            server_fields(),
        ),
        kind(
            "software_license",
            "Software License",
            "software",
            Developer,
            true,
            software_fields(),
        ),
        kind(
            "wireless_router",
            "Wireless Router",
            "router",
            Developer,
            true,
            router_fields(),
        ),
        kind("prompt", "Prompt", "prompt", AgentKnowledge, true, vec![]),
        kind(
            "runbook",
            "Runbook",
            "runbook",
            AgentKnowledge,
            true,
            vec![],
        ),
        kind("note", "Note", "note", AgentKnowledge, true, vec![]),
        kind("generic", "Generic", "item", Other, true, vec![]),
    ]
}

fn identity_document_fields() -> Vec<ItemFieldDefinition> {
    vec![
        text("name", "Name", "person_name", "License", &["full name"]),
        secret(
            "number",
            "License number",
            "identity_number",
            "License",
            &["license no", "id number"],
        ),
        text("class", "Class", "license_class", "License", &["type"]),
        text(
            "region",
            "State/Country",
            "issuing_region",
            "License",
            &["state", "country"],
        ),
        field(
            "issued",
            "Issued",
            "date",
            "issued",
            Sensitivity::PrivateMetadata,
            false,
            "Validity",
            &["issue date"],
        ),
        field(
            "expiry",
            "Expiry",
            "date",
            "expiry",
            Sensitivity::PrivateMetadata,
            false,
            "Validity",
            &["expiration"],
        ),
    ]
}

fn passport_fields() -> Vec<ItemFieldDefinition> {
    vec![
        text("type", "Type", "passport_type", "Passport", &[]),
        secret(
            "number",
            "Passport number",
            "identity_number",
            "Passport",
            &["passport no"],
        ),
        text("name", "Name", "person_name", "Holder", &["full name"]),
        text("nationality", "Nationality", "nationality", "Holder", &[]),
        field(
            "birth_date",
            "Birth date",
            "date",
            "birth_date",
            Sensitivity::PrivateMetadata,
            false,
            "Holder",
            &["dob"],
        ),
        text(
            "birth_place",
            "Birth place",
            "birth_place",
            "Holder",
            &["place of birth"],
        ),
        field(
            "issued",
            "Issued",
            "date",
            "issued",
            Sensitivity::PrivateMetadata,
            false,
            "Validity",
            &["issue date"],
        ),
        field(
            "expiry",
            "Expiry",
            "date",
            "expiry",
            Sensitivity::PrivateMetadata,
            false,
            "Validity",
            &["expiration"],
        ),
        text(
            "authority",
            "Authority",
            "issuer",
            "Validity",
            &["issuing authority"],
        ),
    ]
}

fn membership_fields() -> Vec<ItemFieldDefinition> {
    vec![
        text(
            "organization",
            "Organization/Program",
            "organization",
            "Membership",
            &["program"],
        ),
        text(
            "member_name",
            "Member",
            "person_name",
            "Membership",
            &["name"],
        ),
        secret(
            "member_number",
            "Member number",
            "membership_number",
            "Membership",
            &["member id", "membership no"],
        ),
        secret("pin", "PIN", "pin", "Membership", &["pin"]),
        field(
            "expiry",
            "Expiry",
            "date",
            "expiry",
            Sensitivity::PrivateMetadata,
            false,
            "Membership",
            &["expiration"],
        ),
        url("website", "Website", "website", "Contact", &["url"]),
    ]
}

fn email_fields() -> Vec<ItemFieldDefinition> {
    vec![
        field(
            "email",
            "Email",
            "email",
            "Account",
            Sensitivity::PrivateMetadata,
            false,
            "Account",
            &["email address"],
        ),
        text("provider", "Provider", "provider", "Account", &["service"]),
        text("username", "Username", "username", "Credential", &["user"]),
        secret("password", "Password", "password", "Credential", &["pass"]),
        text(
            "imap_host",
            "IMAP host",
            "imap_host",
            "Incoming",
            &["incoming server"],
        ),
        field(
            "imap_port",
            "IMAP port",
            "number",
            "imap_port",
            Sensitivity::PrivateMetadata,
            false,
            "Incoming",
            &[],
        ),
        text(
            "smtp_host",
            "SMTP host",
            "smtp_host",
            "Outgoing",
            &["outgoing server"],
        ),
        field(
            "smtp_port",
            "SMTP port",
            "number",
            "smtp_port",
            Sensitivity::PrivateMetadata,
            false,
            "Outgoing",
            &[],
        ),
    ]
}

fn server_fields() -> Vec<ItemFieldDefinition> {
    vec![
        text(
            "host",
            "Host/IP",
            "host",
            "Server",
            &["hostname", "server", "ip"],
        ),
        url("url", "URL", "website", "Server", &["website", "admin url"]),
        text(
            "provider",
            "Provider",
            "provider",
            "Server",
            &["hosting provider"],
        ),
        field(
            "port",
            "Port",
            "number",
            "port",
            Sensitivity::PrivateMetadata,
            false,
            "Server",
            &[],
        ),
        text("username", "Username", "username", "Credential", &["user"]),
        secret("password", "Password", "password", "Credential", &["pass"]),
    ]
}

fn software_fields() -> Vec<ItemFieldDefinition> {
    vec![
        text("product", "Product", "product", "License", &["software"]),
        text("version", "Version", "version", "License", &[]),
        text(
            "licensed_to",
            "Licensed to",
            "person_name",
            "License",
            &["registered name"],
        ),
        field(
            "registered_email",
            "Registered email",
            "email",
            "email",
            Sensitivity::PrivateMetadata,
            false,
            "License",
            &["email"],
        ),
        secret(
            "license_key",
            "License key",
            "license_key",
            "License",
            &["serial", "key"],
        ),
        text(
            "order_number",
            "Order number",
            "order_number",
            "Purchase",
            &["order id"],
        ),
        field(
            "purchase_date",
            "Purchase date",
            "date",
            "purchase_date",
            Sensitivity::PrivateMetadata,
            false,
            "Purchase",
            &[],
        ),
        url(
            "download_url",
            "Download URL",
            "download_url",
            "Links",
            &["download"],
        ),
    ]
}

fn router_fields() -> Vec<ItemFieldDefinition> {
    vec![
        text(
            "device",
            "Device/Model",
            "device",
            "Wi-Fi",
            &["router", "model"],
        ),
        text(
            "ssid",
            "Network name",
            "ssid",
            "Wi-Fi",
            &["wifi name", "network"],
        ),
        text(
            "security",
            "Security",
            "wifi_security",
            "Wi-Fi",
            &["wireless security"],
        ),
        secret(
            "wifi_password",
            "Wi-Fi password",
            "wifi_password",
            "Wi-Fi",
            &["wireless password", "network key"],
        ),
        url(
            "admin_url",
            "Admin URL/IP",
            "admin_url",
            "Administration",
            &["server", "ip", "router url"],
        ),
        text(
            "admin_username",
            "Admin username",
            "username",
            "Administration",
            &["username"],
        ),
        secret(
            "admin_password",
            "Admin password",
            "password",
            "Administration",
            &["password"],
        ),
    ]
}

pub fn item_kind(kind_id: &str) -> Option<ItemKindDefinition> {
    builtin_item_kinds()
        .into_iter()
        .find(|item| item.kind == kind_id)
}

pub fn is_agent_content_kind(kind_id: &str) -> bool {
    matches!(kind_id, "core.prompt" | "core.runbook" | "core.note")
}

pub fn normalize_field_alias(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn semantic_role_for(kind_id: &str, key: &str, label: &str) -> Option<String> {
    let candidates = [normalize_field_alias(key), normalize_field_alias(label)];
    item_kind(kind_id).and_then(|kind| {
        kind.fields.into_iter().find_map(|field| {
            let matches = candidates.iter().any(|candidate| {
                *candidate == normalize_field_alias(&field.key)
                    || *candidate == normalize_field_alias(&field.semantic_role)
                    || field
                        .aliases
                        .iter()
                        .any(|alias| *candidate == normalize_field_alias(alias))
            });
            matches.then_some(field.semantic_role)
        })
    })
}

pub fn validate_builtin_item_kinds() -> Result<(), String> {
    let mut kinds = BTreeSet::new();
    for kind in builtin_item_kinds() {
        if !kinds.insert(kind.kind.clone()) {
            return Err(format!("duplicate kind {}", kind.kind));
        }
        let mut keys = BTreeSet::new();
        for field in kind.fields {
            if !keys.insert(field.key.clone()) {
                return Err(format!("duplicate field {} in {}", field.key, kind.kind));
            }
            if matches!(
                field.sensitivity,
                Sensitivity::Secret | Sensitivity::HighlySensitive
            ) && !field.protected
            {
                return Err(format!("secret field {} is not protected", field.key));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_is_complete_and_safe() {
        validate_builtin_item_kinds().unwrap();
        let kinds = builtin_item_kinds();
        assert_eq!(kinds.len(), 26);
        for required in [
            "core.credit_card",
            "core.crypto_wallet",
            "core.ssh_key",
            "core.prompt",
            "core.runbook",
            "core.note",
        ] {
            assert!(kinds.iter().any(|item| item.kind == required));
        }
    }
}
