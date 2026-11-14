//! Importing plain-text formats: `.env` files and password-manager CSV
//! exports. Both are plaintext secrets on disk: the CLI asks for an explicit
//! acknowledgement before reading them.

use super::*;

const MAX_TEXT_IMPORT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENV_VARIABLES: usize = 500;
const MAX_CSV_ROWS: usize = 10_000;

/// Parses a `.env` file into ordered `NAME → value` pairs.
///
/// Supports `export NAME=…`, comments, `'single'` (literal) and `"double"`
/// quotes (with `\n`, `\t`, `\"` and `\\` escapes, possibly over several
/// lines), and `# comments` after unquoted values. A repeated name keeps the
/// last value, as shells do.
pub fn parse_dotenv(content: &str) -> Result<Vec<(String, Zeroizing<String>)>> {
    let invalid = |line: usize, reason: &str| KeyLeaseError::InvalidRequest {
        reason: format!(".env line {line}: {reason}"),
    };
    let mut variables: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut lines = content.lines().enumerate().peekable();
    while let Some((index, raw)) = lines.next() {
        let number = index + 1;
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let (name, rest) = line
            .split_once('=')
            .ok_or_else(|| invalid(number, "expected NAME=VALUE"))?;
        let name = name.trim();
        if !valid_env_key(name) {
            return Err(invalid(number, "invalid variable name"));
        }
        let rest = rest.trim_start();
        let value = if let Some(quoted) = rest.strip_prefix('\'') {
            let end = quoted
                .find('\'')
                .ok_or_else(|| invalid(number, "unterminated single quote"))?;
            Zeroizing::new(quoted[..end].to_owned())
        } else if let Some(quoted) = rest.strip_prefix('"') {
            let mut text = Zeroizing::new(quoted.to_owned());
            loop {
                if let Some(end) = closing_quote(&text) {
                    text.truncate(end);
                    break;
                }
                let Some((_, next)) = lines.next() else {
                    return Err(invalid(number, "unterminated double quote"));
                };
                text.push('\n');
                text.push_str(next);
            }
            Zeroizing::new(unescape_double(&text))
        } else {
            let value = match rest.find(" #") {
                Some(comment) => &rest[..comment],
                None => rest,
            };
            Zeroizing::new(value.trim_end().to_owned())
        };
        variables.retain(|(known, _)| known != name);
        variables.push((name.to_owned(), value));
        if variables.len() > MAX_ENV_VARIABLES {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("an env file holds at most {MAX_ENV_VARIABLES} variables"),
            });
        }
    }
    Ok(variables)
}

fn closing_quote(text: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        match character {
            '\\' if !escaped => escaped = true,
            '"' if !escaped => return Some(index),
            _ => escaped = false,
        }
    }
    None
}

fn unescape_double(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match characters.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Parses RFC 4180 CSV (quoted fields may hold commas, quotes and newlines).
fn parse_csv(content: &str) -> Result<Vec<Vec<Zeroizing<String>>>> {
    let mut rows = Vec::new();
    let mut row: Vec<Zeroizing<String>> = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut characters = content.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(character) = characters.next() {
        if quoted {
            match character {
                '"' if characters.peek() == Some(&'"') => {
                    characters.next();
                    field.push('"');
                }
                '"' => quoted = false,
                _ => field.push(character),
            }
            continue;
        }
        match character {
            '"' if field.is_empty() => quoted = true,
            ',' => row.push(std::mem::replace(&mut field, Zeroizing::new(String::new()))),
            '\r' => {}
            '\n' => {
                row.push(std::mem::replace(&mut field, Zeroizing::new(String::new())));
                if !(row.len() == 1 && row[0].is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
                if rows.len() > MAX_CSV_ROWS {
                    return Err(KeyLeaseError::InvalidRequest {
                        reason: format!("a CSV import holds at most {MAX_CSV_ROWS} rows"),
                    });
                }
            }
            _ => field.push(character),
        }
    }
    if quoted {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "CSV has an unterminated quoted field".into(),
        });
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

/// Which column holds what, from the header row of common exports
/// (browsers, password managers).
#[derive(Default)]
struct CsvColumns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
}

impl CsvColumns {
    fn from_header(header: &[Zeroizing<String>]) -> Result<Self> {
        let mut columns = Self::default();
        for (index, name) in header.iter().enumerate() {
            let name = name.trim().to_ascii_lowercase().replace([' ', '-'], "_");
            let slot = match name.as_str() {
                "name" | "title" | "account" | "item_name" => &mut columns.title,
                "url" | "uri" | "website" | "login_uri" | "web_site" | "origin_url" => {
                    &mut columns.url
                }
                "username" | "user" | "login" | "login_username" | "email" | "user_name" => {
                    &mut columns.username
                }
                "password" | "login_password" | "pass" => &mut columns.password,
                "note" | "notes" | "extra" | "comments" => &mut columns.notes,
                "totp" | "otp" | "login_totp" | "otpauth" | "one_time_password" => {
                    &mut columns.totp
                }
                _ => continue,
            };
            if slot.is_none() {
                *slot = Some(index);
            }
        }
        if columns.password.is_none() && columns.username.is_none() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the CSV header has no username or password column".into(),
            });
        }
        Ok(columns)
    }
}

/// What a text import created.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextImportReport {
    pub created: usize,
    pub skipped: usize,
    pub group: String,
}

impl KeyLeaseService {
    /// Stores a `.env` file as one env-file item (`core.environment`) in a
    /// project (owner command). Every value is stored as a protected secret.
    pub fn import_env_file(
        &self,
        content: &str,
        project_slug: &str,
        environment: Option<&str>,
        title: &str,
        source: &str,
    ) -> Result<ItemMetadata> {
        if content.len() > MAX_TEXT_IMPORT_BYTES {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the file is too large".into(),
            });
        }
        let variables = parse_dotenv(content)?;
        if variables.is_empty() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the file has no variables".into(),
            });
        }
        validate_item_title(title)?;
        self.with_vault(|vault| {
            let projects = self.store.list_projects(vault)?;
            let project = projects
                .iter()
                .find(|project| project.slug == project_slug)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("project {project_slug}"),
                })?;
            let environment = resolve_item_environment(Some(project), environment)?;
            let text = |key: &str, label: &str, role: &str, value: &str| ItemField {
                semantic_role: Some(role.into()),
                ..field(
                    key,
                    label,
                    FieldValue::Text(value.into()),
                    Sensitivity::PrivateMetadata,
                    false,
                )
            };
            let metadata = vec![
                text(
                    "environment.project",
                    "Project / repository",
                    "environment_project",
                    &project.slug,
                ),
                text(
                    "environment.scope",
                    "Environment",
                    "environment_scope",
                    environment.as_deref().unwrap_or("default"),
                ),
                text("environment.source", "Source", "environment_source", source),
            ];
            let variables: Vec<ItemField> = variables
                .iter()
                .map(|(name, value)| ItemField {
                    semantic_role: Some("environment_variable".into()),
                    ..field(
                        &format!("env.{name}"),
                        name,
                        FieldValue::Concealed(value.to_string()),
                        Sensitivity::HighlySensitive,
                        true,
                    )
                })
                .collect();
            let sections = vec![
                ItemSection {
                    id: "environment_metadata".into(),
                    label: "Environment".into(),
                    field_ids: metadata.iter().map(|field| field.id.clone()).collect(),
                    semantic_role: Some("environment_metadata".into()),
                },
                ItemSection {
                    id: "environment_variables".into(),
                    label: "Variables".into(),
                    field_ids: variables.iter().map(|field| field.id.clone()).collect(),
                    semantic_role: Some("environment_variables".into()),
                },
            ];
            let mut fields = metadata;
            fields.extend(variables);
            validate_custom_fields(&fields)?;
            validate_sections(&sections, &fields)?;
            validate_specialized_item("core.environment", &sections, &fields)?;
            let group = self.import_group(vault, "Env files")?;
            let now = Utc::now();
            let item = VaultItem {
                id: ItemId::new(),
                vault_id: vault.vault_id.clone(),
                group_id: group.id,
                kind: "core.environment".into(),
                title: title.into(),
                sections,
                fields,
                urls: vec![],
                tags: vec![],
                favorite: false,
                attachments: vec![],
                notes: None,
                template_version: item_kind("core.environment")
                    .map(|definition| definition.template_version)
                    .unwrap_or(1),
                project_id: Some(project.id.clone()),
                agent_access: AgentAccess::None,
                content_metadata: None,
                personal: false,
                schema_version: 1,
                revision: 1,
                created_at: now,
                updated_at: now,
                secret_changed_at: Some(now),
                expires_at: None,
                rotation_interval_days: None,
                issuer: None,
                environment,
                owner: None,
                status: ItemStatus::Active,
                extensions: Default::default(),
            };
            self.put_owner_item(vault, &item, "env-import")?;
            Ok(item.metadata())
        })
    }

    /// Imports logins from a CSV export into the Personal area (owner
    /// command). Rows without a username and a password are skipped.
    pub fn import_logins_csv(&self, content: &str, group_name: &str) -> Result<TextImportReport> {
        if content.len() > MAX_TEXT_IMPORT_BYTES {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the file is too large".into(),
            });
        }
        let rows = parse_csv(content)?;
        let (header, rows) = rows
            .split_first()
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: "the CSV file is empty".into(),
            })?;
        let columns = CsvColumns::from_header(header)?;
        self.with_vault(|vault| {
            let group = self.import_group(vault, group_name)?;
            let mut report = TextImportReport {
                created: 0,
                skipped: 0,
                group: group.name.clone(),
            };
            let cell = |row: &[Zeroizing<String>], column: Option<usize>| -> Option<String> {
                column
                    .and_then(|index| row.get(index))
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
            };
            for row in rows {
                let username = cell(row, columns.username);
                let password = cell(row, columns.password).map(Zeroizing::new);
                if username.is_none() && password.is_none() {
                    report.skipped += 1;
                    continue;
                }
                let url = cell(row, columns.url);
                let title = cell(row, columns.title)
                    .or_else(|| {
                        url.as_ref().and_then(|url| {
                            url::Url::parse(url).ok()?.host_str().map(str::to_owned)
                        })
                    })
                    .or_else(|| username.clone())
                    .unwrap_or_else(|| "Imported login".into());
                let title: String = title.chars().take(200).collect();
                let mut fields = Vec::new();
                if let Some(username) = &username {
                    fields.push(field(
                        "username",
                        "Username",
                        FieldValue::Text(username.clone()),
                        Sensitivity::PrivateMetadata,
                        false,
                    ));
                }
                if let Some(password) = &password {
                    fields.push(field(
                        "password",
                        "Password",
                        FieldValue::Concealed(password.to_string()),
                        Sensitivity::Secret,
                        true,
                    ));
                }
                if let Some(totp) = cell(row, columns.totp) {
                    let mut config = None;
                    let mut uri = Some(totp);
                    if normalize_totp(&mut config, &mut uri).is_ok()
                        && let Some(config) = config
                    {
                        fields.push(field(
                            "otp",
                            "One-time password",
                            FieldValue::Totp(config),
                            Sensitivity::Secret,
                            true,
                        ));
                    }
                }
                let now = Utc::now();
                let item = VaultItem {
                    id: ItemId::new(),
                    vault_id: vault.vault_id.clone(),
                    group_id: group.id.clone(),
                    kind: "core.login".into(),
                    title,
                    sections: vec![],
                    fields,
                    urls: url
                        .into_iter()
                        .map(|url| ItemUrl { label: None, url })
                        .collect(),
                    tags: vec![],
                    favorite: false,
                    attachments: vec![],
                    notes: cell(row, columns.notes),
                    template_version: item_kind("core.login")
                        .map(|definition| definition.template_version)
                        .unwrap_or(1),
                    project_id: None,
                    agent_access: AgentAccess::None,
                    content_metadata: None,
                    personal: true,
                    schema_version: 1,
                    revision: 1,
                    created_at: now,
                    updated_at: now,
                    secret_changed_at: password.as_ref().map(|_| now),
                    expires_at: None,
                    rotation_interval_days: None,
                    issuer: None,
                    environment: None,
                    owner: None,
                    status: ItemStatus::Active,
                    extensions: Default::default(),
                };
                self.put_owner_item(vault, &item, "csv-import")?;
                report.created += 1;
            }
            Ok(report)
        })
    }

    /// The group with this name, created when missing.
    pub(crate) fn import_group(&self, vault: &UnlockedVault, name: &str) -> Result<VaultGroup> {
        let groups = self.store.list_groups(vault)?;
        if let Some(group) = groups.iter().find(|group| group.name == name) {
            return Ok(group.clone());
        }
        validate_group(name, None, &groups)?;
        let now = Utc::now();
        let group = VaultGroup {
            id: GroupId::new(),
            vault_id: vault.vault_id.clone(),
            parent_id: None,
            name: name.into(),
            purpose: GroupPurpose::User,
            sort_order: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        self.store.put_group(vault, &group, Some(0), None)?;
        Ok(group)
    }

    pub(crate) fn put_owner_item(
        &self,
        vault: &UnlockedVault,
        item: &VaultItem,
        operation: &str,
    ) -> Result<()> {
        let idempotency_key = random_token(operation);
        let request_material = operation_material(&serde_json::json!({
            "operation": operation,
            "item": item.id,
            "revision": item.revision,
        }))?;
        self.store.put_item(
            vault,
            item,
            Some(item.revision - 1),
            MutationContext {
                actor: "owner",
                idempotency_key: &idempotency_key,
                request_material: &request_material,
                audit_event: None,
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_handles_quotes_comments_exports_and_repeats() {
        let parsed = parse_dotenv(
            "# comment\nexport API_KEY=abc123 # trailing\nEMPTY=\nSINGLE='a $b # c'\n\
             DOUBLE=\"line1\\nline2 \\\"q\\\"\"\nMULTI=\"one\ntwo\"\nAPI_KEY=override\n",
        )
        .unwrap();
        let get = |name: &str| {
            parsed
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str().to_owned())
        };
        assert_eq!(get("API_KEY").as_deref(), Some("override"));
        assert_eq!(get("EMPTY").as_deref(), Some(""));
        assert_eq!(get("SINGLE").as_deref(), Some("a $b # c"));
        assert_eq!(get("DOUBLE").as_deref(), Some("line1\nline2 \"q\""));
        assert_eq!(get("MULTI").as_deref(), Some("one\ntwo"));
        assert_eq!(parsed.len(), 5);
        assert!(parse_dotenv("1BAD=x").is_err());
        assert!(parse_dotenv("NOEQUALS").is_err());
        assert!(parse_dotenv("A=\"open").is_err());
    }

    #[test]
    fn csv_parses_quoted_fields_and_maps_common_headers() {
        let rows = parse_csv(
            "\u{feff}name,url,username,password,note\r\n\"Bank, Inc\",https://bank.example,me,\"p\"\"w\",\"two\nlines\"\n\n",
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][0].as_str(), "Bank, Inc");
        assert_eq!(rows[1][3].as_str(), "p\"w");
        assert_eq!(rows[1][4].as_str(), "two\nlines");
        let columns = CsvColumns::from_header(&rows[0]).unwrap();
        assert_eq!(
            (
                columns.title,
                columns.url,
                columns.username,
                columns.password,
                columns.notes
            ),
            (Some(0), Some(1), Some(2), Some(3), Some(4))
        );
        let header = |names: &[&str]| {
            names
                .iter()
                .map(|name| Zeroizing::new((*name).to_owned()))
                .collect::<Vec<_>>()
        };
        assert!(CsvColumns::from_header(&header(&["title", "notes"])).is_err());
        assert!(parse_csv("a,\"b").is_err());
    }
}
