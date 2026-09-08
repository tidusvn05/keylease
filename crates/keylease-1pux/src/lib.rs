//! Bounded 1Password Unencrypted Export (1PUX) import adapter.
//!
//! 1PUX input is plaintext. This crate never writes an extracted archive to disk;
//! attachment content is placed in the imported item's encrypted extension bag.

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use keylease_core::{
    AddressValue, AgentAccess, FieldId, FieldValue, GroupId, GroupPurpose, ItemField, ItemStatus,
    ItemUrl, KeyLeaseError, Result, Sensitivity, TotpAlgorithm, TotpConfig, VaultGroup, VaultId,
    VaultItem, semantic_role_for,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{Cursor, Read, Seek},
    path::Path,
};
use zip::ZipArchive;

pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXPORT_DATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const SUPPORTED_FORMAT_VERSION: u64 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationReport {
    pub format: String,
    pub format_version: u64,
    pub source_checksum_sha256: String,
    pub successful_items: u64,
    pub successful_groups: u64,
    pub warnings: Vec<String>,
    pub unsupported_fields: Vec<String>,
    pub duplicate_decisions: Vec<String>,
    pub attachment_count: u64,
    pub attachment_bytes: u64,
    pub history_versions: u64,
}

#[derive(Debug, Clone)]
pub struct ImportPreview {
    pub groups: Vec<VaultGroup>,
    pub items: Vec<VaultItem>,
    pub report: MigrationReport,
}

pub trait OnePuxAdapter {
    fn preview_import(&self, source: &mut dyn Read, vault_id: &VaultId) -> Result<ImportPreview>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ZipOnePuxAdapter;

impl OnePuxAdapter for ZipOnePuxAdapter {
    fn preview_import(&self, source: &mut dyn Read, vault_id: &VaultId) -> Result<ImportPreview> {
        let bytes = read_source(source)?;
        let checksum = hex(&Sha256::digest(&bytes));
        let mut archive =
            ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid("invalid 1PUX ZIP archive"))?;
        validate_archive(&mut archive)?;

        let attributes: Value = serde_json::from_slice(&read_entry(
            &mut archive,
            "export.attributes",
            MAX_EXPORT_DATA_BYTES as u64,
        )?)
        .map_err(|_| invalid("invalid export.attributes JSON"))?;
        let version = attributes
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("export.attributes has no numeric version"))?;
        if version > SUPPORTED_FORMAT_VERSION {
            return Err(KeyLeaseError::UnsupportedVersion {
                version: u32::try_from(version).unwrap_or(u32::MAX),
            });
        }

        let data: Value = serde_json::from_slice(&read_entry(
            &mut archive,
            "export.data",
            MAX_EXPORT_DATA_BYTES as u64,
        )?)
        .map_err(|_| invalid("invalid export.data JSON"))?;
        let attachments = load_attachments(&mut archive)?;
        convert_export(data, attachments, vault_id, version, checksum)
    }
}

fn read_source(source: &mut dyn Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KeyLeaseError::Storage)?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(invalid("1PUX archive exceeds the 64 MiB source limit"));
    }
    Ok(bytes)
}

fn validate_archive<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<()> {
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(invalid("1PUX archive has too many entries"));
    }
    let mut expanded = 0_u64;
    let mut paths = HashSet::new();
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_| invalid("invalid ZIP entry"))?;
        let Some(path) = file.enclosed_name() else {
            return Err(invalid("1PUX archive contains an unsafe path"));
        };
        if !paths.insert(path) {
            return Err(invalid("1PUX archive contains a duplicate entry path"));
        }
        expanded = expanded
            .checked_add(file.size())
            .ok_or_else(|| invalid("1PUX expanded size overflow"))?;
        if expanded > MAX_EXPANDED_BYTES {
            return Err(invalid("1PUX archive exceeds the 256 MiB expanded limit"));
        }
    }
    Ok(())
}

fn read_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let file = archive
        .by_name(name)
        .map_err(|_| invalid(&format!("1PUX archive is missing {name}")))?;
    read_zip_file(file, limit, name)
}

fn read_zip_file<R: Read>(mut file: R, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid(&format!("unable to read {label}")))?;
    if bytes.len() as u64 > limit {
        return Err(invalid(&format!("{label} exceeds its size limit")));
    }
    Ok(bytes)
}

fn load_attachments<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<HashMap<String, Vec<u8>>> {
    let mut attachments = HashMap::new();
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_| invalid("invalid ZIP entry"))?;
        let Some(path) = file.enclosed_name() else {
            return Err(invalid("1PUX archive contains an unsafe path"));
        };
        let path_text = path.to_string_lossy().replace('\\', "/");
        if !path_text.starts_with("files/") || file.is_dir() {
            continue;
        }
        if file.size() > MAX_ATTACHMENT_BYTES {
            return Err(invalid(&format!(
                "attachment {path_text} exceeds the 32 MiB limit"
            )));
        }
        let content = read_zip_file(file, MAX_ATTACHMENT_BYTES, &path_text)?;
        attachments.insert(path_text, content);
    }
    Ok(attachments)
}

fn convert_export(
    data: Value,
    attachments: HashMap<String, Vec<u8>>,
    vault_id: &VaultId,
    version: u64,
    checksum: String,
) -> Result<ImportPreview> {
    let accounts = data
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("export.data has no accounts array"))?;
    let now = Utc::now();
    let mut preview = ImportPreview {
        groups: Vec::new(),
        items: Vec::new(),
        report: MigrationReport {
            format: "1pux".into(),
            format_version: version,
            source_checksum_sha256: checksum,
            successful_items: 0,
            successful_groups: 0,
            warnings: vec![
                "1PUX input is unencrypted plaintext; keep it out of backups and indexes and delete it after verifying the import".into(),
            ],
            unsupported_fields: Vec::new(),
            duplicate_decisions: Vec::new(),
            attachment_count: 0,
            attachment_bytes: 0,
            history_versions: 0,
        },
    };

    for (account_index, account) in accounts.iter().enumerate() {
        let attrs = account.get("attrs").unwrap_or(&Value::Null);
        let account_uuid =
            text_at(attrs, "uuid").unwrap_or_else(|| format!("account-{account_index}"));
        let account_group_id = GroupId(stable_id("group_1p_account", &account_uuid, account_index));
        preview.groups.push(VaultGroup {
            id: account_group_id.clone(),
            vault_id: vault_id.clone(),
            parent_id: None,
            name: text_at(attrs, "accountName")
                .or_else(|| text_at(attrs, "name"))
                .unwrap_or_else(|| "1Password Account".into()),
            purpose: GroupPurpose::User,
            sort_order: Some(account_index as u32),
            revision: 1,
            created_at: now,
            updated_at: now,
        });
        let vaults = account
            .get("vaults")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("1PUX account has no vaults array"))?;
        for (vault_index, source_vault) in vaults.iter().enumerate() {
            let vault_attrs = source_vault.get("attrs").unwrap_or(&Value::Null);
            let source_vault_uuid = text_at(vault_attrs, "uuid")
                .unwrap_or_else(|| format!("vault-{account_index}-{vault_index}"));
            let group_id = GroupId(stable_id("group_1p_vault", &source_vault_uuid, vault_index));
            preview.groups.push(VaultGroup {
                id: group_id.clone(),
                vault_id: vault_id.clone(),
                parent_id: Some(account_group_id.clone()),
                name: text_at(vault_attrs, "name").unwrap_or_else(|| "1Password Vault".into()),
                purpose: GroupPurpose::User,
                sort_order: Some(vault_index as u32),
                revision: 1,
                created_at: now,
                updated_at: now,
            });
            let items = source_vault
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("1PUX vault has no items array"))?;
            for (item_index, source_item) in items.iter().enumerate() {
                let item = convert_item(
                    source_item,
                    vault_id,
                    &group_id,
                    &source_vault_uuid,
                    item_index,
                    &attachments,
                    &mut preview.report,
                )?;
                preview.items.push(item);
            }
        }
    }
    preview.report.successful_groups = preview.groups.len() as u64;
    preview.report.successful_items = preview.items.len() as u64;
    Ok(preview)
}

#[allow(clippy::too_many_arguments)]
fn convert_item(
    source: &Value,
    vault_id: &VaultId,
    group_id: &GroupId,
    source_vault_uuid: &str,
    item_index: usize,
    archive_files: &HashMap<String, Vec<u8>>,
    report: &mut MigrationReport,
) -> Result<VaultItem> {
    let source_uuid = text_at(source, "uuid").unwrap_or_else(|| format!("item-{item_index}"));
    let item_id = keylease_core::ItemId(stable_id(
        "item_1p",
        &format!("{source_vault_uuid}_{source_uuid}"),
        item_index,
    ));
    let details = source.get("details").unwrap_or(&Value::Null);
    let overview = source.get("overview").unwrap_or(&Value::Null);
    let created_at = timestamp_at(source, "createdAt").unwrap_or_else(Utc::now);
    let updated_at = timestamp_at(source, "updatedAt").unwrap_or(created_at);
    let category = text_at(source, "categoryUuid").unwrap_or_else(|| "unknown".into());
    let mut fields = Vec::new();
    let mut sections = Vec::new();

    if let Some(login_fields) = details.get("loginFields").and_then(Value::as_array) {
        let mut field_ids = Vec::new();
        for (index, field) in login_fields.iter().enumerate() {
            let designation = text_at(field, "designation");
            let source_name = text_at(field, "name").unwrap_or_else(|| format!("field_{index}"));
            let key = designation.clone().unwrap_or_else(|| source_name.clone());
            let field_type = text_at(field, "fieldType")
                .or_else(|| text_at(field, "type"))
                .unwrap_or_else(|| "T".into());
            let raw = text_at(field, "value").unwrap_or_default();
            let (value, sensitivity, protected) =
                login_value(&field_type, &raw, designation.as_deref());
            let id = FieldId(stable_id(
                "field_1p_login",
                &format!("{source_uuid}_{index}"),
                index,
            ));
            field_ids.push(id.clone());
            fields.push(ItemField {
                id,
                key,
                label: source_name,
                value,
                sensitivity,
                protected,
                semantic_role: None,
            });
        }
        if !field_ids.is_empty() {
            sections.push(keylease_core::ItemSection {
                id: format!("section_1p_login_{item_index}"),
                label: "Login".into(),
                field_ids,
            });
        }
    }

    if let Some(source_sections) = details.get("sections").and_then(Value::as_array) {
        for (section_index, source_section) in source_sections.iter().enumerate() {
            let mut field_ids = Vec::new();
            if let Some(source_fields) = source_section.get("fields").and_then(Value::as_array) {
                for (field_index, source_field) in source_fields.iter().enumerate() {
                    let raw_value = source_field.get("value").unwrap_or(&Value::Null);
                    let context =
                        format!("{source_uuid}/section-{section_index}/field-{field_index}");
                    let (value, sensitivity, protected, source_type) =
                        typed_value(raw_value, &context, report);
                    let label = text_at(source_field, "title")
                        .or_else(|| text_at(source_field, "id"))
                        .unwrap_or_else(|| format!("Field {}", field_index + 1));
                    let id = FieldId(stable_id("field_1p_custom", &context, field_index));
                    field_ids.push(id.clone());
                    fields.push(ItemField {
                        id,
                        key: text_at(source_field, "id")
                            .filter(|value| !value.is_empty())
                            .unwrap_or_else(|| format!("custom_{section_index}_{field_index}")),
                        label,
                        value,
                        sensitivity,
                        protected,
                        semantic_role: None,
                    });
                    if source_type == "unsupported" {
                        report.unsupported_fields.push(context);
                    }
                }
            }
            sections.push(keylease_core::ItemSection {
                id: text_at(source_section, "name")
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("section_1p_{item_index}_{section_index}")),
                label: text_at(source_section, "title")
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("Section {}", section_index + 1)),
                field_ids,
            });
        }
    }

    let mut extensions = BTreeMap::new();
    extensions.insert("onepux.source_item_uuid".into(), json!(source_uuid));
    extensions.insert("onepux.source_vault_uuid".into(), json!(source_vault_uuid));
    extensions.insert("onepux.category_uuid".into(), json!(category));
    if let Some(favorite) = source.get("favIndex") {
        extensions.insert("onepux.favorite_index".into(), favorite.clone());
    }
    if let Some(history) = details.get("passwordHistory").and_then(Value::as_array) {
        report.history_versions += history.len() as u64;
        extensions.insert(
            "onepux.password_history".into(),
            Value::Array(history.clone()),
        );
    }
    let (attachment_names, encoded_attachments) =
        collect_item_attachments(source, details, archive_files, report);
    if !encoded_attachments.is_empty() {
        extensions.insert(
            "onepux.attachments".into(),
            Value::Array(encoded_attachments),
        );
    }

    let kind = onepux_kind(&category);
    for field in &mut fields {
        field.semantic_role = semantic_role_for(&kind, &field.key, &field.label);
        harden_semantic_field(field);
    }

    Ok(VaultItem {
        id: item_id,
        vault_id: vault_id.clone(),
        group_id: group_id.clone(),
        kind,
        title: text_at(overview, "title").unwrap_or_else(|| "Untitled".into()),
        sections,
        fields,
        urls: urls_from_overview(overview),
        tags: overview
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        favorite: source
            .get("favIndex")
            .and_then(Value::as_i64)
            .is_some_and(|index| index > 0),
        attachments: attachment_names,
        notes: text_at(details, "notesPlain"),
        template_version: 1,
        project_id: None,
        agent_access: AgentAccess::None,
        content_metadata: None,
        schema_version: 1,
        revision: 1,
        created_at,
        updated_at,
        secret_changed_at: None,
        expires_at: None,
        rotation_interval_days: None,
        issuer: None,
        environment: None,
        owner: None,
        status: if text_at(source, "state").as_deref() == Some("archived") {
            ItemStatus::Archived
        } else {
            ItemStatus::Active
        },
        extensions,
    })
}

fn onepux_kind(category: &str) -> String {
    match category {
        "001" => "core.login",
        "002" => "core.credit_card",
        "003" => "core.secure_note",
        "004" => "core.identity",
        "005" => "core.password",
        "006" => "core.document",
        "100" => "core.software_license",
        "101" => "core.bank_account",
        "102" => "core.database",
        "103" => "core.driver_license",
        "104" => "core.outdoor_license",
        "105" => "core.membership",
        "106" => "core.passport",
        "107" => "core.reward_program",
        "108" => "core.social_security_number",
        "109" => "core.wireless_router",
        "110" => "core.server",
        "111" => "core.email_account",
        "112" => "core.api_credential",
        "113" => "core.medical_record",
        "114" => "core.ssh_key",
        other => return format!("onepassword.category_{other}"),
    }
    .into()
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

fn login_value(
    field_type: &str,
    raw: &str,
    designation: Option<&str>,
) -> (FieldValue, Sensitivity, bool) {
    if designation == Some("password") || field_type.eq_ignore_ascii_case("P") {
        return (
            FieldValue::Concealed(raw.into()),
            Sensitivity::HighlySensitive,
            true,
        );
    }
    match field_type.to_ascii_uppercase().as_str() {
        "E" => (
            FieldValue::Email(raw.into()),
            Sensitivity::PrivateMetadata,
            false,
        ),
        "U" => (
            FieldValue::Url(raw.into()),
            Sensitivity::PrivateMetadata,
            false,
        ),
        "TEL" => (
            FieldValue::Phone(raw.into()),
            Sensitivity::PrivateMetadata,
            false,
        ),
        "N" => raw.parse::<f64>().map_or_else(
            |_| {
                (
                    FieldValue::Text(raw.into()),
                    Sensitivity::PrivateMetadata,
                    false,
                )
            },
            |number| {
                (
                    FieldValue::Number(number),
                    Sensitivity::PrivateMetadata,
                    false,
                )
            },
        ),
        _ => (
            FieldValue::Text(raw.into()),
            Sensitivity::PrivateMetadata,
            false,
        ),
    }
}

fn typed_value(
    raw: &Value,
    context: &str,
    report: &mut MigrationReport,
) -> (FieldValue, Sensitivity, bool, &'static str) {
    let Some(object) = raw.as_object() else {
        return match raw {
            Value::String(value) => (
                FieldValue::Text(value.clone()),
                Sensitivity::PrivateMetadata,
                false,
                "string",
            ),
            Value::Number(value) => (
                FieldValue::Number(value.as_f64().unwrap_or_default()),
                Sensitivity::PrivateMetadata,
                false,
                "number",
            ),
            Value::Bool(value) => (
                FieldValue::Boolean(*value),
                Sensitivity::PrivateMetadata,
                false,
                "boolean",
            ),
            _ => unsupported_value(raw, context, report),
        };
    };
    if object.len() != 1 {
        return unsupported_value(raw, context, report);
    }
    let (kind, value) = object.iter().next().expect("single-entry object");
    let text = value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string());
    match normalize_type(kind).as_str() {
        "concealed" | "creditcardnumber" => (
            FieldValue::Concealed(text),
            Sensitivity::HighlySensitive,
            true,
            "concealed",
        ),
        "email" => (
            FieldValue::Email(text),
            Sensitivity::PrivateMetadata,
            false,
            "email",
        ),
        "url" => (
            FieldValue::Url(text),
            Sensitivity::PrivateMetadata,
            false,
            "url",
        ),
        "phone" => (
            FieldValue::Phone(text),
            Sensitivity::PrivateMetadata,
            false,
            "phone",
        ),
        "date" => (
            FieldValue::Date(text),
            Sensitivity::PrivateMetadata,
            false,
            "date",
        ),
        "monthyear" => parse_month_year(value).map_or_else(
            || unsupported_value(raw, context, report),
            |(month, year)| {
                (
                    FieldValue::MonthYear { month, year },
                    Sensitivity::PrivateMetadata,
                    false,
                    "month_year",
                )
            },
        ),
        "address" => parse_address(value).map_or_else(
            || unsupported_value(raw, context, report),
            |address| {
                (
                    FieldValue::Address(address),
                    Sensitivity::PrivateMetadata,
                    false,
                    "address",
                )
            },
        ),
        "reference" => (
            FieldValue::Reference(text),
            Sensitivity::PrivateMetadata,
            false,
            "reference",
        ),
        "onetimepassword" | "totp" => (parse_totp(&text), Sensitivity::Secret, true, "totp"),
        "string" | "creditcardtype" | "gender" | "menu" => (
            FieldValue::Text(text),
            Sensitivity::PrivateMetadata,
            false,
            "string",
        ),
        _ => unsupported_value(raw, context, report),
    }
}

fn unsupported_value(
    raw: &Value,
    context: &str,
    report: &mut MigrationReport,
) -> (FieldValue, Sensitivity, bool, &'static str) {
    report.warnings.push(format!(
        "{context}: unsupported typed value retained as protected JSON"
    ));
    (
        FieldValue::OpaqueJson(raw.clone()),
        Sensitivity::Secret,
        true,
        "unsupported",
    )
}

fn parse_month_year(value: &Value) -> Option<(u8, u16)> {
    if let Some(object) = value.as_object() {
        let month = object.get("month")?.as_u64()? as u8;
        let year = object.get("year")?.as_u64()? as u16;
        return (month > 0 && month <= 12).then_some((month, year));
    }
    if let Some(packed) = value.as_u64() {
        let month = (packed % 100) as u8;
        let year = (packed / 100) as u16;
        return (month > 0 && month <= 12 && year >= 1900).then_some((month, year));
    }
    let raw = value.as_str()?.trim();
    if raw.len() == 6 && raw.chars().all(|character| character.is_ascii_digit()) {
        let packed = raw.parse::<u64>().ok()?;
        let month = (packed % 100) as u8;
        let year = (packed / 100) as u16;
        return (month > 0 && month <= 12 && year >= 1900).then_some((month, year));
    }
    let (left, right) = raw.split_once(['/', '-'])?;
    let (month, mut year) = if left.len() == 4 {
        (right.parse::<u8>().ok()?, left.parse::<u16>().ok()?)
    } else {
        (left.parse::<u8>().ok()?, right.parse::<u16>().ok()?)
    };
    if year < 100 {
        year += 2000;
    }
    (month > 0 && month <= 12).then_some((month, year))
}

fn parse_address(value: &Value) -> Option<AddressValue> {
    let object = value.as_object()?;
    Some(AddressValue {
        street: object
            .get("street")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        city: object
            .get("city")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        state: object
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        postal_code: object
            .get("zip")
            .or_else(|| object.get("postalCode"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        country: object
            .get("country")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
    })
}

fn parse_totp(raw: &str) -> FieldValue {
    let Ok(url) = url::Url::parse(raw) else {
        return FieldValue::Concealed(raw.into());
    };
    if url.scheme() != "otpauth" {
        return FieldValue::Concealed(raw.into());
    }
    let mut secret = String::new();
    let mut issuer = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6;
    let mut period = 30;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = value.into_owned(),
            "issuer" => issuer = Some(value.into_owned()),
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => TotpAlgorithm::Sha1,
                }
            }
            "digits" => digits = value.parse().unwrap_or(6),
            "period" => period = value.parse().unwrap_or(30),
            _ => {}
        }
    }
    FieldValue::Totp(TotpConfig {
        secret_base32: secret,
        issuer,
        account: (!url.path().trim_start_matches('/').is_empty())
            .then(|| url.path().trim_start_matches('/').to_owned()),
        algorithm,
        digits,
        period,
        source_representation: Some(raw.into()),
    })
}

fn collect_item_attachments(
    source: &Value,
    details: &Value,
    archive_files: &HashMap<String, Vec<u8>>,
    report: &mut MigrationReport,
) -> (Vec<String>, Vec<Value>) {
    let explicit_path = source
        .get("file")
        .and_then(|file| file.get("path"))
        .and_then(Value::as_str);
    let document = details.get("documentAttributes");
    let document_id = document
        .and_then(|value| value.get("documentId"))
        .and_then(Value::as_str);
    let declared_name = document
        .and_then(|value| value.get("fileName"))
        .and_then(Value::as_str);
    let mut matches = archive_files
        .iter()
        .filter(|(path, _)| {
            explicit_path.is_some_and(|candidate| candidate == path.as_str())
                || document_id.is_some_and(|id| {
                    Path::new(path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(&format!("{id}___")))
                })
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|(path, _)| path.as_str());
    let mut names = Vec::new();
    let mut encoded = Vec::new();
    for (path, content) in matches {
        let archive_name = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("attachment");
        let name = declared_name.map(str::to_owned).unwrap_or_else(|| {
            archive_name
                .split_once("___")
                .map_or(archive_name, |(_, name)| name)
                .to_owned()
        });
        names.push(name.clone());
        encoded.push(json!({
            "name": name,
            "source_path": path,
            "document_id": document_id,
            "content_base64": STANDARD.encode(content),
        }));
        report.attachment_count += 1;
        report.attachment_bytes += content.len() as u64;
    }
    if (explicit_path.is_some() || document_id.is_some()) && encoded.is_empty() {
        report.warnings.push(format!(
            "attachment {} is referenced but missing from the archive",
            explicit_path.or(document_id).unwrap_or("unknown")
        ));
    }
    (names, encoded)
}

fn urls_from_overview(overview: &Value) -> Vec<ItemUrl> {
    let mut urls = overview
        .get("urls")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    Some(ItemUrl {
                        label: text_at(value, "label").filter(|label| !label.is_empty()),
                        url: text_at(value, "url")?,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if urls.is_empty()
        && let Some(url) = text_at(overview, "url").filter(|url| !url.is_empty())
    {
        urls.push(ItemUrl { label: None, url });
    }
    urls
}

fn text_at(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn timestamp_at(value: &Value, key: &str) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(value.get(key)?.as_i64()?, 0)
}

fn normalize_type(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn stable_id(prefix: &str, source: &str, fallback: usize) -> String {
    let normalized = source
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if normalized.is_empty() {
        format!("{prefix}_{fallback}")
    } else {
        format!("{prefix}_{normalized}")
    }
}

fn invalid(reason: &str) -> KeyLeaseError {
    KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn fixture_archive() -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut output);
            let options = SimpleFileOptions::default();
            zip.start_file("export.attributes", options).unwrap();
            zip.write_all(include_bytes!(
                "../../../test-vectors/onepux/export.attributes"
            ))
            .unwrap();
            zip.start_file("export.data", options).unwrap();
            zip.write_all(include_bytes!("../../../test-vectors/onepux/export.data"))
                .unwrap();
            zip.start_file("files/documentfixture000000000001___recovery.txt", options)
                .unwrap();
            zip.write_all(include_bytes!(
                "../../../test-vectors/onepux/files/documentfixture000000000001___recovery.txt"
            ))
            .unwrap();
            zip.finish().unwrap();
        }
        output.into_inner()
    }

    #[test]
    fn fixture_preserves_structure_types_history_and_attachment_bytes() {
        let bytes = fixture_archive();
        let vault = VaultId::new();
        let preview = ZipOnePuxAdapter
            .preview_import(&mut bytes.as_slice(), &vault)
            .unwrap();
        assert_eq!(preview.groups.len(), 2);
        assert_eq!(preview.items.len(), 1);
        let item = &preview.items[0];
        assert_eq!(item.kind, "core.login");
        assert_eq!(item.sections.len(), 2);
        assert!(item.fields.iter().any(|field| {
            field.key == "password"
                && field.protected
                && matches!(field.value, FieldValue::Concealed(_))
        }));
        assert!(
            item.fields
                .iter()
                .any(|field| matches!(field.value, FieldValue::Email(_)))
        );
        assert_eq!(item.attachments, ["recovery.txt"]);
        let attachments = item.extensions["onepux.attachments"].as_array().unwrap();
        let decoded = STANDARD
            .decode(attachments[0]["content_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            decoded,
            include_bytes!(
                "../../../test-vectors/onepux/files/documentfixture000000000001___recovery.txt"
            )
        );
        assert_eq!(preview.report.history_versions, 1);
        assert_eq!(preview.report.attachment_count, 1);
        assert_eq!(preview.report.unsupported_fields.len(), 0);
    }

    #[test]
    fn rejects_future_format_versions() {
        let data = include_bytes!("../../../test-vectors/onepux/export.data");
        let mut output = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut output);
            let options = SimpleFileOptions::default();
            zip.start_file("export.attributes", options).unwrap();
            zip.write_all(br#"{"version": 99}"#).unwrap();
            zip.start_file("export.data", options).unwrap();
            zip.write_all(data).unwrap();
            zip.finish().unwrap();
        }
        let error = ZipOnePuxAdapter
            .preview_import(&mut output.into_inner().as_slice(), &VaultId::new())
            .unwrap_err();
        assert_eq!(error, KeyLeaseError::UnsupportedVersion { version: 99 });
    }

    #[test]
    fn month_year_accepts_onepassword_packed_and_display_forms() {
        assert_eq!(parse_month_year(&json!(202709)), Some((9, 2027)));
        assert_eq!(parse_month_year(&json!("2027-09")), Some((9, 2027)));
        assert_eq!(parse_month_year(&json!("09/27")), Some((9, 2027)));
        assert_eq!(parse_month_year(&json!(202713)), None);
    }
}
