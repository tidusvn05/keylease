//! KDBX 3.1/4.x import and KDBX 4.1 export behind an adapter boundary.

use chrono::{DateTime, Utc};
use keepass::{
    Database, DatabaseKey,
    db::{GroupRef, fields},
};
use keylease_core::{
    AddressValue, AgentAccess, FieldId, FieldValue, GroupId, GroupPurpose, ItemField, ItemStatus,
    ItemUrl, KeyLeaseError, Result, Sensitivity, TotpAlgorithm, TotpConfig, VaultGroup, VaultId,
    VaultItem, normalize_field_alias, semantic_role_for,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationReport {
    pub format: String,
    pub source_checksum_sha256: Option<String>,
    pub successful_items: u64,
    pub warnings: Vec<String>,
    pub unsupported_fields: Vec<String>,
    pub duplicate_decisions: Vec<String>,
    pub attachment_count: u64,
    pub history_versions: u64,
}
impl MigrationReport {
    fn new(format: &str) -> Self {
        Self {
            format: format.into(),
            source_checksum_sha256: None,
            successful_items: 0,
            warnings: vec![],
            unsupported_fields: vec![],
            duplicate_decisions: vec![],
            attachment_count: 0,
            history_versions: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportPreview {
    pub groups: Vec<VaultGroup>,
    pub items: Vec<VaultItem>,
    pub report: MigrationReport,
}

pub trait KdbxAdapter {
    fn preview_import(
        &self,
        source: &mut dyn Read,
        password: &str,
        vault_id: &VaultId,
    ) -> Result<ImportPreview>;
    fn export(
        &self,
        destination: &mut dyn Write,
        password: &str,
        groups: &[VaultGroup],
        items: &[VaultItem],
    ) -> Result<MigrationReport>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct KeepassRsAdapter;

impl KdbxAdapter for KeepassRsAdapter {
    fn preview_import(
        &self,
        source: &mut dyn Read,
        password: &str,
        vault_id: &VaultId,
    ) -> Result<ImportPreview> {
        let mut bytes = Vec::new();
        source
            .read_to_end(&mut bytes)
            .map_err(|_| KeyLeaseError::Storage)?;
        let checksum = hex(&Sha256::digest(&bytes));
        let database = Database::parse(&bytes, DatabaseKey::new().with_password(password))
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "unable to open KDBX (wrong password or invalid file)".into(),
            })?;
        let mut preview = ImportPreview {
            groups: vec![],
            items: vec![],
            report: MigrationReport::new("kdbx"),
        };
        preview.report.source_checksum_sha256 = Some(checksum);
        walk_group(database.root(), None, vault_id, &mut preview);
        preview.report.successful_items = preview.items.len() as u64;
        Ok(preview)
    }

    fn export(
        &self,
        destination: &mut dyn Write,
        password: &str,
        groups: &[VaultGroup],
        items: &[VaultItem],
    ) -> Result<MigrationReport> {
        let mut database = Database::new();
        database.root_mut().name = "KeyLease Export".into();
        let mut group_map: HashMap<String, keepass::db::GroupId> = HashMap::new();
        let root_id = database.root().id();
        let mut pending: Vec<_> = groups.iter().collect();
        let mut progress = true;
        while !pending.is_empty() && progress {
            progress = false;
            let mut rest = vec![];
            for group in pending {
                let parent = match &group.parent_id {
                    None => Some(root_id),
                    Some(id) => group_map.get(&id.0).copied(),
                };
                if let Some(parent) = parent {
                    let keepass_id = uuid_from_prefixed(&group.id.0)
                        .map(keepass::db::GroupId::from_uuid)
                        .unwrap_or_else(keepass::db::GroupId::new);
                    database
                        .group_mut(parent)
                        .ok_or(KeyLeaseError::Storage)?
                        .add_group_with_id(keepass_id)
                        .map_err(|_| KeyLeaseError::Storage)?
                        .name = group.name.clone();
                    group_map.insert(group.id.0.clone(), keepass_id);
                    progress = true
                } else {
                    rest.push(group)
                }
            }
            pending = rest;
        }
        let mut report = MigrationReport::new("kdbx4.1");
        if !pending.is_empty() {
            report
                .warnings
                .push("some group parents were missing; groups were exported at root".into());
            for group in pending {
                let id = database.root_mut().add_group().id();
                database.group_mut(id).expect("new group").name = group.name.clone();
                group_map.insert(group.id.0.clone(), id);
            }
        }
        for item in items {
            let parent = group_map.get(&item.group_id.0).copied().unwrap_or(root_id);
            let eid = uuid_from_prefixed(&item.id.0)
                .map(keepass::db::EntryId::from_uuid)
                .unwrap_or_else(keepass::db::EntryId::new);
            let mut parent_group = database.group_mut(parent).ok_or(KeyLeaseError::Storage)?;
            let mut entry = parent_group
                .add_entry_with_id(eid)
                .map_err(|_| KeyLeaseError::Storage)?;
            entry.set_unprotected(fields::TITLE, &item.title);
            if let Some(url) = item.urls.first() {
                entry.set_unprotected(fields::URL, &url.url);
            }
            if let Some(notes) = &item.notes {
                entry.set_protected(fields::NOTES, notes);
            }
            entry.set_protected("KeyLease.Kind", &item.kind);
            entry.set_protected("KeyLease.SchemaVersion", item.schema_version.to_string());
            entry.set_protected(
                "KeyLease.TemplateVersion",
                item.template_version.to_string(),
            );
            if !item.sections.is_empty() {
                let sections =
                    serde_json::to_string(&item.sections).map_err(|_| KeyLeaseError::Storage)?;
                entry.set_protected("KeyLease.Sections", sections);
            }
            entry.tags = item.tags.clone();
            for field in &item.fields {
                let key = match field.key.as_str() {
                    "username" => fields::USERNAME,
                    "password" => fields::PASSWORD,
                    "otp" => fields::OTP,
                    other => other,
                };
                let value = field_to_string(&field.value);
                if field.protected
                    || matches!(
                        field.sensitivity,
                        Sensitivity::Secret | Sensitivity::HighlySensitive
                    )
                {
                    entry.set_protected(key, value)
                } else {
                    entry.set_unprotected(key, value)
                }
                entry.set_protected(format!("KeyLease.FieldId.{}", field.key), &field.id.0);
                if let Some(role) = &field.semantic_role {
                    entry.set_protected(format!("KeyLease.SemanticRole.{}", field.key), role);
                }
            }
            if !item.attachments.is_empty() {
                report.attachment_count += item.attachments.len() as u64;
                report.warnings.push(format!(
                    "{} attachment references on {} require binary material and were not exported",
                    item.attachments.len(),
                    item.id.0
                ));
            }
            report.successful_items += 1;
        }
        database
            .save(destination, DatabaseKey::new().with_password(password))
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(report)
    }
}

fn walk_group(
    group: GroupRef<'_>,
    parent: Option<GroupId>,
    vault_id: &VaultId,
    preview: &mut ImportPreview,
) {
    let group_id = GroupId(format!("group_{}", group.id().uuid().simple()));
    let now = Utc::now();
    preview.groups.push(VaultGroup {
        id: group_id.clone(),
        vault_id: vault_id.clone(),
        parent_id: parent,
        name: if group.name.is_empty() {
            "Root".into()
        } else {
            group.name.clone()
        },
        purpose: GroupPurpose::User,
        sort_order: None,
        revision: 1,
        created_at: now,
        updated_at: now,
    });
    for entry in group.entries() {
        let item_id = keylease_core::ItemId(format!("item_{}", entry.id().uuid().simple()));
        let created = entry
            .times
            .creation
            .map(|n| DateTime::from_naive_utc_and_offset(n, Utc))
            .unwrap_or(now);
        let updated = entry
            .times
            .last_modification
            .map(|n| DateTime::from_naive_utc_and_offset(n, Utc))
            .unwrap_or(now);
        let mut item = VaultItem {
            id: item_id,
            vault_id: vault_id.clone(),
            group_id: group_id.clone(),
            kind: entry.get("KeyLease.Kind").unwrap_or("core.login").into(),
            title: entry.get_title().unwrap_or("Untitled").into(),
            sections: entry
                .get("KeyLease.Sections")
                .and_then(|value| serde_json::from_str(value).ok())
                .unwrap_or_default(),
            fields: vec![],
            urls: entry
                .get_url()
                .filter(|v| !v.is_empty())
                .map(|url| {
                    vec![ItemUrl {
                        label: None,
                        url: url.into(),
                    }]
                })
                .unwrap_or_default(),
            tags: entry.tags.clone(),
            favorite: false,
            attachments: vec![],
            notes: entry.get(fields::NOTES).map(str::to_owned),
            template_version: entry
                .get("KeyLease.TemplateVersion")
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
            project_id: None,
            agent_access: AgentAccess::None,
            content_metadata: None,
            schema_version: entry
                .get("KeyLease.SchemaVersion")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            revision: 1,
            created_at: created,
            updated_at: updated,
            secret_changed_at: None,
            expires_at: None,
            rotation_interval_days: None,
            issuer: None,
            environment: None,
            owner: None,
            status: ItemStatus::Active,
            extensions: BTreeMap::new(),
        };
        item.extensions
            .insert("kdbx.source".into(), serde_json::json!(true));
        let has_otp = entry.get(fields::OTP).is_some();
        if !has_otp && let Some(secret) = entry.get("TimeOtp-Secret-Base32") {
            let algorithm = match entry
                .get("TimeOtp-Algorithm")
                .unwrap_or("SHA1")
                .to_ascii_uppercase()
                .as_str()
            {
                "SHA256" => TotpAlgorithm::Sha256,
                "SHA512" => TotpAlgorithm::Sha512,
                _ => TotpAlgorithm::Sha1,
            };
            let period = entry
                .get("TimeOtp-Period")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30);
            let digits = entry
                .get("TimeOtp-Length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(6);
            item.fields.push(ItemField {
                id: FieldId::new(),
                key: "otp".into(),
                label: "TOTP".into(),
                value: FieldValue::Totp(TotpConfig {
                    secret_base32: secret.into(),
                    issuer: None,
                    account: Some(item.title.clone()),
                    algorithm,
                    digits,
                    period,
                    source_representation: None,
                }),
                sensitivity: Sensitivity::Secret,
                protected: true,
                semantic_role: Some("otp".into()),
            });
            item.extensions.insert(
                "kdbx.totp_representation".into(),
                serde_json::json!("keepass_timeotp_fields"),
            );
        }
        for (name, value) in &entry.fields {
            if [
                fields::TITLE,
                fields::URL,
                fields::NOTES,
                "KeyLease.Kind",
                "KeyLease.SchemaVersion",
                "KeyLease.TemplateVersion",
                "KeyLease.Sections",
            ]
            .contains(&name.as_str())
                || name.starts_with("KeyLease.FieldId.")
                || name.starts_with("KeyLease.SemanticRole.")
                || (!has_otp
                    && matches!(
                        name.as_str(),
                        "TimeOtp-Secret-Base32"
                            | "TimeOtp-Algorithm"
                            | "TimeOtp-Period"
                            | "TimeOtp-Length"
                    ))
            {
                continue;
            }
            let key = match name.as_str() {
                fields::USERNAME => "username",
                fields::PASSWORD => "password",
                fields::OTP => "otp",
                other => other,
            };
            let sensitivity = if value.is_protected() {
                Sensitivity::Secret
            } else {
                Sensitivity::PrivateMetadata
            };
            let field_value = if key == "otp" {
                parse_totp(value.as_str())
            } else if value.is_protected() {
                FieldValue::Concealed(value.as_str().into())
            } else {
                FieldValue::Text(value.as_str().into())
            };
            let stable = entry
                .get(&format!("KeyLease.FieldId.{key}"))
                .map(str::to_owned)
                .unwrap_or_else(|| FieldId::new().0);
            item.fields.push(ItemField {
                id: FieldId(stable),
                key: key.into(),
                label: name.clone(),
                value: field_value,
                sensitivity,
                protected: value.is_protected(),
                semantic_role: entry
                    .get(&format!("KeyLease.SemanticRole.{key}"))
                    .map(str::to_owned),
            });
        }
        if entry.get("KeyLease.Kind").is_none() {
            item.kind = infer_kdbx_kind(&item);
        }
        for field in &mut item.fields {
            if field.semantic_role.is_none() {
                field.semantic_role = semantic_role_for(&item.kind, &field.key, &field.label);
            }
            harden_semantic_field(field);
        }
        for (name, attachment) in entry.attachments_named() {
            item.attachments.push(name.into());
            preview.report.attachment_count += 1;
            preview.report.warnings.push(format!(
                "attachment {name} ({} bytes) retained as migration metadata only",
                attachment.data.get().len()
            ));
        }
        if let Some(history) = &entry.history {
            preview.report.history_versions += history.get_entries().len() as u64;
            item.extensions.insert(
                "kdbx.history_count".into(),
                serde_json::json!(history.get_entries().len()),
            );
        }
        preview.items.push(item);
    }
    for child in group.groups() {
        walk_group(child, Some(group_id.clone()), vault_id, preview);
    }
}

fn parse_totp(raw: &str) -> FieldValue {
    if let Ok(url) = url::Url::parse(raw)
        && url.scheme() == "otpauth"
    {
        let mut secret = String::new();
        let mut issuer = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "secret" => secret = v.into_owned(),
                "issuer" => issuer = Some(v.into_owned()),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => TotpAlgorithm::Sha1,
                    }
                }
                "digits" => digits = v.parse().unwrap_or(6),
                "period" => period = v.parse().unwrap_or(30),
                _ => {}
            }
        }
        let account = url.path().trim_start_matches('/');
        return FieldValue::Totp(TotpConfig {
            secret_base32: secret,
            issuer,
            account: (!account.is_empty()).then(|| account.to_owned()),
            algorithm,
            digits,
            period,
            source_representation: Some(raw.into()),
        });
    }
    FieldValue::Concealed(raw.into())
}
fn field_to_string(value: &FieldValue) -> String {
    match value {
        FieldValue::Text(v)
        | FieldValue::Concealed(v)
        | FieldValue::Url(v)
        | FieldValue::Email(v)
        | FieldValue::Phone(v)
        | FieldValue::Date(v)
        | FieldValue::Certificate(v)
        | FieldValue::AttachmentRef(v)
        | FieldValue::Reference(v) => v.clone(),
        FieldValue::MonthYear { month, year } => format!("{month:02}/{year}"),
        FieldValue::Address(AddressValue {
            street,
            city,
            state,
            postal_code,
            country,
        }) => [street, city, state, postal_code, country]
            .into_iter()
            .filter(|part| !part.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        FieldValue::OpaqueJson(value) => value.to_string(),
        FieldValue::Number(v) => v.to_string(),
        FieldValue::Boolean(v) => v.to_string(),
        FieldValue::Totp(v) => v.source_representation.clone().unwrap_or_else(|| {
            format!(
                "otpauth://totp/{}?secret={}&algorithm={:?}&digits={}&period={}",
                v.account.as_deref().unwrap_or("KeyLease"),
                v.secret_base32,
                v.algorithm,
                v.digits,
                v.period
            )
        }),
        FieldValue::KeyPair { public, private } => format!("{public}\n{private}"),
    }
}

fn infer_kdbx_kind(item: &VaultItem) -> String {
    let names = item
        .fields
        .iter()
        .flat_map(|field| [&field.key, &field.label])
        .map(|value| normalize_field_alias(value))
        .collect::<Vec<_>>();
    let has = |aliases: &[&str]| {
        names.iter().any(|name| {
            aliases
                .iter()
                .any(|alias| name == &normalize_field_alias(alias))
        })
    };
    if has(&["card number", "credit card number", "cc number"])
        && has(&["expiry", "expiry date", "expiration"])
    {
        "core.credit_card".into()
    } else if has(&["private key", "ssh private key"])
        || has(&["public key", "ssh public key"]) && has(&["fingerprint"])
    {
        "core.ssh_key".into()
    } else if has(&["password", "pass", "passwd"])
        && (has(&["username", "user", "login"]) || !item.urls.is_empty())
    {
        "core.login".into()
    } else if item.fields.is_empty()
        && item.urls.is_empty()
        && item
            .notes
            .as_deref()
            .is_some_and(|notes| !notes.trim().is_empty())
    {
        "core.secure_note".into()
    } else {
        "core.generic".into()
    }
}

fn harden_semantic_field(field: &mut ItemField) {
    if matches!(
        field.semantic_role.as_deref(),
        Some(
            "password"
                | "credential"
                | "client_secret"
                | "card_number"
                | "card_verification"
                | "pin"
                | "account_number"
                | "routing_number"
                | "iban"
                | "swift"
                | "identity_number"
                | "private_key"
                | "passphrase"
                | "recovery_phrase"
                | "license_key"
                | "connection_string"
                | "wifi_password"
        )
    ) {
        field.sensitivity = Sensitivity::HighlySensitive;
        field.protected = true;
        if let FieldValue::Text(value) = &field.value {
            field.value = FieldValue::Concealed(value.clone());
        }
    }
}
fn uuid_from_prefixed(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value.split_once('_')?.1).ok()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylease_core::ItemId;
    #[test]
    fn kdbx_41_round_trip_custom_protected_and_totp() {
        let vault = VaultId::new();
        let group = VaultGroup {
            id: GroupId::new(),
            vault_id: vault.clone(),
            parent_id: None,
            name: "Development".into(),
            purpose: GroupPurpose::User,
            sort_order: None,
            revision: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let credential_id = FieldId::new();
        let otp_id = FieldId::new();
        let item = VaultItem {
            id: ItemId::new(),
            vault_id: vault.clone(),
            group_id: group.id.clone(),
            kind: "core.api_credential".into(),
            title: "GitHub".into(),
            sections: vec![keylease_core::ItemSection {
                id: "api_credentials".into(),
                label: "API credentials".into(),
                field_ids: vec![credential_id.clone(), otp_id.clone()],
                semantic_role: Some("api_credentials".into()),
            }],
            fields: vec![
                ItemField {
                    id: credential_id,
                    key: "credential".into(),
                    label: "Token".into(),
                    value: FieldValue::Concealed("ghp_secret".into()),
                    sensitivity: Sensitivity::Secret,
                    protected: true,
                    semantic_role: Some("credential".into()),
                },
                ItemField {
                    id: otp_id,
                    key: "otp".into(),
                    label: "otp".into(),
                    value: parse_totp("otpauth://totp/acme?secret=JBSWY3DPEHPK3PXP&issuer=Acme"),
                    sensitivity: Sensitivity::Secret,
                    protected: true,
                    semantic_role: Some("otp".into()),
                },
            ],
            urls: vec![],
            tags: vec![],
            favorite: false,
            attachments: vec![],
            notes: None,
            template_version: 2,
            project_id: None,
            agent_access: AgentAccess::None,
            content_metadata: None,
            schema_version: 1,
            revision: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            secret_changed_at: None,
            expires_at: None,
            rotation_interval_days: None,
            issuer: None,
            environment: None,
            owner: None,
            status: ItemStatus::Active,
            extensions: Default::default(),
        };
        let mut bytes = vec![];
        let report = KeepassRsAdapter
            .export(
                &mut bytes,
                "password",
                &[group],
                std::slice::from_ref(&item),
            )
            .unwrap();
        assert_eq!(report.successful_items, 1);
        let imported = KeepassRsAdapter
            .preview_import(&mut bytes.as_slice(), "password", &vault)
            .unwrap();
        assert_eq!(imported.items.len(), 1);
        assert_eq!(imported.items[0].kind, "core.api_credential");
        assert_eq!(imported.items[0].template_version, 2);
        assert_eq!(imported.items[0].sections, item.sections);
        assert_eq!(
            imported.items[0].fields[0].semantic_role.as_deref(),
            Some("credential")
        );
        assert!(
            imported.items[0]
                .fields
                .iter()
                .any(|f| f.key == "otp" && matches!(f.value, FieldValue::Totp(_)))
        );
    }
}
