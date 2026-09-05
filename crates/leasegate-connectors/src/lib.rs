//! LeaseGate connector contract, built-in manifests and fake conformance provider.

use async_trait::async_trait;
use keylease_core::{
    ActionRequest, ActionResponse, ContentAccess, DataBudget, KeyLeaseError, Result, RiskTier,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    pub provider: String,
    pub version: String,
    pub authentication_methods: Vec<String>,
    pub fixed_https_origins: Vec<String>,
    pub actions: Vec<ActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub name: String,
    pub resource_prefix: String,
    pub risk: RiskTier,
    pub allowed_fields: BTreeMap<String, JsonType>,
    pub required_fields: BTreeSet<String>,
    pub content_access: ContentAccess,
    pub default_budget: DataBudget,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JsonType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthCredential {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub scopes: Vec<String>,
}
impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuthCredential([REDACTED])")
    }
}
impl Drop for OAuthCredential {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(value) = &mut self.refresh_token {
            value.zeroize()
        }
        if let Some(value) = &mut self.client_secret {
            value.zeroize()
        }
    }
}

#[derive(Clone)]
pub struct ConnectorCredential(String);
impl ConnectorCredential {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn bearer_token(&self) -> Cow<'_, str> {
        serde_json::from_str::<Value>(&self.0)
            .ok()
            .and_then(|value| {
                value
                    .get("access_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .map_or_else(|| Cow::Borrowed(self.0.as_str()), Cow::Owned)
    }
    pub fn oauth(&self) -> Option<OAuthCredential> {
        serde_json::from_str(&self.0).ok()
    }
}

pub fn validate_connection_credential(provider: &str, value: &str) -> Result<()> {
    if provider != "google_workspace" {
        return Ok(());
    }
    let credential: OAuthCredential =
        serde_json::from_str(value).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "Google Workspace requires a structured OAuth credential".into(),
        })?;
    if credential.scopes != ["https://www.googleapis.com/auth/drive.file".to_owned()] {
        return Err(KeyLeaseError::Denied {
            reason: "Google Workspace credential must contain only the drive.file scope".into(),
        });
    }
    Ok(())
}
impl std::fmt::Debug for ConnectorCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectorCredential([REDACTED])")
    }
}
impl Drop for ConnectorCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct CanonicalAction {
    pub request: ActionRequest,
    pub spec: ActionSpec,
}

#[async_trait]
pub trait Connector: Send + Sync {
    fn manifest(&self) -> ConnectorManifest;
    async fn canonicalize(&self, request: &ActionRequest) -> Result<CanonicalAction> {
        validate_and_canonicalize(&self.manifest(), request)
    }
    async fn execute(
        &self,
        action: &CanonicalAction,
        credential: &ConnectorCredential,
    ) -> Result<ActionResponse>;
    async fn test_connection(&self, credential: &ConnectorCredential) -> Result<()>;
    async fn refresh(
        &self,
        credential: &ConnectorCredential,
    ) -> Result<Option<ConnectorCredential>>;
    async fn revoke(&self, credential: &ConnectorCredential) -> Result<()>;
}

pub fn validate_and_canonicalize(
    manifest: &ConnectorManifest,
    request: &ActionRequest,
) -> Result<CanonicalAction> {
    request.validate_version()?;
    let spec = manifest
        .actions
        .iter()
        .find(|s| s.name == request.action)
        .cloned()
        .ok_or_else(|| KeyLeaseError::Denied {
            reason: "unknown connector action".into(),
        })?;
    if request.resource.chars().any(char::is_control) || !request.resource.is_ascii() {
        return Err(KeyLeaseError::Denied {
            reason: "resource identifier is not canonical ASCII".into(),
        });
    }
    if request.resource != spec.resource_prefix
        && !request
            .resource
            .strip_prefix(&spec.resource_prefix)
            .is_some_and(|tail| tail.starts_with('/') || tail.starts_with(':'))
    {
        return Err(KeyLeaseError::Denied {
            reason: "resource is outside action namespace".into(),
        });
    }
    let arguments = request
        .arguments
        .as_object()
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "arguments must be an object".into(),
        })?;
    for key in arguments.keys() {
        if !spec.allowed_fields.contains_key(key) {
            return Err(KeyLeaseError::Denied {
                reason: format!("unknown argument field: {key}"),
            });
        }
    }
    for required in &spec.required_fields {
        if !arguments.contains_key(required) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("missing required field: {required}"),
            });
        }
    }
    for (key, value) in arguments {
        if !json_type_matches(value, &spec.allowed_fields[key]) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("invalid type for field: {key}"),
            });
        }
    }
    let mut canonical = request.clone();
    canonical.resource = canonical_resource(&request.resource)?;
    canonical.arguments = canonical_object(arguments);
    Ok(CanonicalAction {
        request: canonical,
        spec,
    })
}

pub fn validate_enrolled_resource(manifest: &ConnectorManifest, resource: &str) -> Result<String> {
    let canonical = canonical_resource(resource)?;
    let object_id = manifest
        .actions
        .iter()
        .find_map(|action| {
            canonical
                .strip_prefix(&format!("{}/", action.resource_prefix))
                .filter(|id| !id.is_empty() && !id.contains('/') && !id.contains(':'))
        })
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "resource does not identify one provider object from the connector manifest"
                .into(),
        })?;
    if manifest.provider == "github" && object_id.parse::<u64>().ok().filter(|id| *id > 0).is_none()
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "GitHub resources must use the stable numeric repository id".into(),
        });
    }
    Ok(canonical)
}

pub fn enforce_response_budget(
    mut response: ActionResponse,
    budget: &DataBudget,
) -> Result<ActionResponse> {
    if budget
        .max_items
        .zip(response.item_count)
        .is_some_and(|(max, actual)| actual > max)
        || budget
            .max_cells
            .zip(response.cell_count)
            .is_some_and(|(max, actual)| actual > max)
    {
        return Err(KeyLeaseError::Denied {
            reason: "response data budget exceeded".into(),
        });
    }
    let bytes = serde_json::to_vec(&response.body)
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?
        .len() as u64;
    if budget.max_response_bytes.is_some_and(|max| bytes > max) {
        return Err(KeyLeaseError::Denied {
            reason: "response byte budget exceeded".into(),
        });
    }
    response.untrusted_content = true;
    Ok(response)
}

pub fn redact_error(input: &str, secrets: &[&str]) -> String {
    let mut result = input.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            result = result.replace(secret, "[REDACTED]");
        }
    }
    result
}

fn canonical_resource(resource: &str) -> Result<String> {
    let trimmed = resource.trim();
    if trimmed != resource
        || resource.contains("//")
        || resource.split('/').any(|part| part == "." || part == "..")
        || resource.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, ':' | '/' | '_' | '-' | '.'))
        })
    {
        return Err(KeyLeaseError::Denied {
            reason: "non-canonical resource alias".into(),
        });
    }
    Ok(resource.to_owned())
}
fn canonical_object(input: &Map<String, Value>) -> Value {
    let mut keys: Vec<_> = input.keys().collect();
    keys.sort();
    Value::Object(
        keys.into_iter()
            .map(|k| (k.clone(), keylease_core::canonical_json(&input[k])))
            .collect(),
    )
}
fn json_type_matches(v: &Value, t: &JsonType) -> bool {
    matches!(
        (v, t),
        (Value::String(_), JsonType::String)
            | (Value::Number(_), JsonType::Number)
            | (Value::Bool(_), JsonType::Boolean)
            | (Value::Array(_), JsonType::Array)
            | (Value::Object(_), JsonType::Object)
    )
}
fn fields(entries: &[(&str, JsonType)]) -> BTreeMap<String, JsonType> {
    entries
        .iter()
        .map(|(k, v)| ((*k).into(), v.clone()))
        .collect()
}
fn required(entries: &[&str]) -> BTreeSet<String> {
    entries.iter().map(|v| (*v).into()).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeFailure {
    None,
    OAuthExpired,
    OAuthDenied,
    Revoked,
    InvalidScope,
    RateLimited,
    Timeout,
    PartialFailure,
    SchemaDrift,
    LeakSecret,
}

#[derive(Clone)]
pub struct FakeConnector {
    state: Arc<Mutex<FakeState>>,
}
#[derive(Debug)]
struct FakeState {
    failure: FakeFailure,
    writes: u64,
    pages: Vec<Value>,
}

impl Default for FakeConnector {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                failure: FakeFailure::None,
                writes: 0,
                pages: vec![
                    serde_json::json!([{"id":"one"}]),
                    serde_json::json!([{"id":"two"}]),
                ],
            })),
        }
    }
}
impl FakeConnector {
    pub fn set_failure(&self, f: FakeFailure) {
        self.state.lock().expect("fake mutex").failure = f
    }
    pub fn writes(&self) -> u64 {
        self.state.lock().expect("fake mutex").writes
    }
}

#[async_trait]
impl Connector for FakeConnector {
    fn manifest(&self) -> ConnectorManifest {
        ConnectorManifest {
            provider: "fake".into(),
            version: "1".into(),
            authentication_methods: vec!["fixture_token".into()],
            fixed_https_origins: vec![],
            actions: vec![
                ActionSpec {
                    name: "fake.resource.read".into(),
                    resource_prefix: "fake:resource".into(),
                    risk: RiskTier::R1,
                    allowed_fields: fields(&[("page", JsonType::Number)]),
                    required_fields: required(&[]),
                    content_access: ContentAccess::BoundedContent,
                    default_budget: DataBudget {
                        max_items: Some(10),
                        max_response_bytes: Some(4096),
                        ..Default::default()
                    },
                    idempotent: true,
                },
                ActionSpec {
                    name: "fake.resource.write".into(),
                    resource_prefix: "fake:resource".into(),
                    risk: RiskTier::R2,
                    allowed_fields: fields(&[("value", JsonType::String)]),
                    required_fields: required(&["value"]),
                    content_access: ContentAccess::None,
                    default_budget: Default::default(),
                    idempotent: false,
                },
            ],
        }
    }
    async fn execute(
        &self,
        action: &CanonicalAction,
        credential: &ConnectorCredential,
    ) -> Result<ActionResponse> {
        let failure = self
            .state
            .lock()
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?
            .failure;
        match failure {
            FakeFailure::OAuthExpired
            | FakeFailure::OAuthDenied
            | FakeFailure::Revoked
            | FakeFailure::InvalidScope => {
                return Err(KeyLeaseError::Denied {
                    reason: "connection authorization unavailable".into(),
                });
            }
            FakeFailure::RateLimited => {
                return Err(KeyLeaseError::ConnectorUnavailable { retryable: true });
            }
            FakeFailure::Timeout => {
                tokio::time::sleep(Duration::from_millis(25)).await;
                return Err(KeyLeaseError::ConnectorUnavailable { retryable: true });
            }
            FakeFailure::LeakSecret => {
                let _safe = redact_error(
                    &format!("upstream leaked {}", credential.expose()),
                    &[credential.expose()],
                );
                return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
            }
            FakeFailure::SchemaDrift => {
                return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
            }
            _ => {}
        }
        let (body, item_count) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
            if action.request.action.ends_with("write") {
                state.writes += 1;
                (serde_json::json!({"written":true}), Some(1))
            } else {
                let page = action
                    .request
                    .arguments
                    .get("page")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                (
                    state
                        .pages
                        .get(page)
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([])),
                    Some(1),
                )
            }
        };
        if failure == FakeFailure::PartialFailure {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: false });
        }
        Ok(ActionResponse {
            provider: "fake".into(),
            connection_id: action.request.connection_id.clone(),
            canonical_resource: action.request.resource.clone(),
            revision: Some(format!("fake-{item_count:?}")),
            untrusted_content: true,
            item_count,
            cell_count: None,
            body,
        })
    }
    async fn test_connection(&self, credential: &ConnectorCredential) -> Result<()> {
        if credential.expose().is_empty() {
            Err(KeyLeaseError::Denied {
                reason: "missing credential".into(),
            })
        } else {
            Ok(())
        }
    }
    async fn refresh(
        &self,
        credential: &ConnectorCredential,
    ) -> Result<Option<ConnectorCredential>> {
        self.test_connection(credential).await?;
        Ok(Some(ConnectorCredential::new(
            "refreshed-fixture-token".into(),
        )))
    }
    async fn revoke(&self, _: &ConnectorCredential) -> Result<()> {
        self.set_failure(FakeFailure::Revoked);
        Ok(())
    }
}

/// Built-in production HTTP connector. Provider origins are fixed; arbitrary URLs are never accepted.
pub struct BuiltinConnector {
    manifest: ConnectorManifest,
    client: reqwest::Client,
}
impl BuiltinConnector {
    pub fn google() -> Self {
        Self::new(google_manifest())
    }
    pub fn github() -> Self {
        Self::new(github_manifest())
    }
    pub fn linear() -> Self {
        Self::new(linear_manifest())
    }
    pub fn notion() -> Self {
        Self::new(notion_manifest())
    }
    fn new(manifest: ConnectorManifest) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .expect("static HTTP client config");
        Self { manifest, client }
    }
}

#[async_trait]
impl Connector for BuiltinConnector {
    fn manifest(&self) -> ConnectorManifest {
        self.manifest.clone()
    }
    async fn canonicalize(&self, request: &ActionRequest) -> Result<CanonicalAction> {
        let mut canonical = validate_and_canonicalize(&self.manifest, request)?;
        if !is_virtual_collection_action(&canonical.request) {
            validate_enrolled_resource(&self.manifest, &canonical.request.resource)?;
        }
        if self.manifest.provider == "github" {
            let repository_id = canonical
                .request
                .resource
                .rsplit('/')
                .next()
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "missing GitHub repository id".into(),
                })?;
            if repository_id
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .is_none()
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "GitHub resources must use the stable numeric repository id".into(),
                });
            }
            if let Some(number) = canonical.request.arguments.get("number")
                && number.as_u64().filter(|value| *value > 0).is_none()
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "GitHub issue and pull-request numbers must be positive integers"
                        .into(),
                });
            }
        }
        if canonical.request.action == "google_sheets.rows.append"
            || canonical.request.action == "google_sheets.values.update"
        {
            let object = canonical
                .request
                .arguments
                .as_object_mut()
                .expect("validated object");
            match object.get("value_input_option").and_then(Value::as_str) {
                Some("RAW") | None => {
                    object.insert("value_input_option".into(), Value::String("RAW".into()));
                }
                Some(_) => return Err(KeyLeaseError::Denied {
                    reason:
                        "formula interpretation is not supported; value_input_option must be RAW"
                            .into(),
                }),
            }
        }
        if canonical
            .request
            .action
            .starts_with("google_sheets.values.")
            || canonical.request.action == "google_sheets.rows.append"
        {
            if let Some(range) = canonical
                .request
                .arguments
                .get("range")
                .and_then(Value::as_str)
            {
                a1_cell_count(range)?;
                a1_sheet_name(range)?;
            }
            if let Some(ranges) = canonical
                .request
                .arguments
                .get("ranges")
                .and_then(Value::as_array)
            {
                if ranges.is_empty() || ranges.len() > 100 {
                    return Err(KeyLeaseError::Denied {
                        reason: "sheet batch must contain between 1 and 100 ranges".into(),
                    });
                }
                for range in ranges {
                    let range = range
                        .as_str()
                        .ok_or_else(|| KeyLeaseError::InvalidRequest {
                            reason: "sheet range must be a string".into(),
                        })?;
                    a1_cell_count(range)?;
                    a1_sheet_name(range)?;
                }
            }
            if let Some(values) = canonical.request.arguments.get("values") {
                let rows = values
                    .as_array()
                    .ok_or_else(|| KeyLeaseError::InvalidRequest {
                        reason: "sheet values must be an array of rows".into(),
                    })?;
                if rows.is_empty()
                    || rows.len() > 10_000
                    || rows
                        .iter()
                        .any(|row| row.as_array().is_none_or(|cells| cells.len() > 10_000))
                {
                    return Err(KeyLeaseError::Denied {
                        reason: "sheet values must be a non-empty bounded array of row arrays"
                            .into(),
                    });
                }
            }
            if canonical.request.action == "google_sheets.values.update" {
                validate_digest_argument(&canonical.request.arguments, "expected_values_hash")?;
            }
        }
        if self.manifest.provider == "notion" {
            if canonical.request.action == "notion.page.create" {
                let parent_id = string_argument(&canonical.request.arguments, "parent_id")?;
                let resource_parent = canonical
                    .request
                    .resource
                    .strip_prefix("notion:page/")
                    .ok_or_else(|| KeyLeaseError::InvalidRequest {
                        reason: "Notion create must target an enrolled parent page".into(),
                    })?;
                if parent_id != resource_parent {
                    return Err(KeyLeaseError::Denied {
                        reason: "Notion parent_id must match the authorized page resource".into(),
                    });
                }
            }
            if canonical.request.action == "notion.page.update_markdown" {
                validate_digest_argument(&canonical.request.arguments, "content_digest")?;
            }
            if let Some(markdown) = canonical
                .request
                .arguments
                .get("markdown")
                .and_then(Value::as_str)
                && (markdown.len() > 1_000_000
                    || markdown.lines().count() > 1000
                    || markdown.lines().any(|line| line.chars().count() > 2000))
            {
                return Err(KeyLeaseError::Denied {
                    reason: "Notion markdown exceeds the bounded block payload".into(),
                });
            }
        }
        Ok(canonical)
    }
    async fn execute(
        &self,
        action: &CanonicalAction,
        credential: &ConnectorCredential,
    ) -> Result<ActionResponse> {
        if is_google_sheet_range_action(&action.request.action) {
            validate_google_sheet_binding(&self.client, action, credential).await?;
        }
        if action.request.action == "notion.page.update_markdown" {
            let block_id = encoded(string_argument(&action.request.arguments, "block_id")?);
            let response = self
                .client
                .get(format!("https://api.notion.com/v1/blocks/{block_id}"))
                .bearer_auth(credential.bearer_token())
                .header("accept", "application/json")
                .header("notion-version", "2025-09-03")
                .send()
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
            if !response.status().is_success() {
                return Err(KeyLeaseError::ConnectorUnavailable {
                    retryable: response.status().is_server_error(),
                });
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(KeyLeaseError::Denied {
                    reason: "preflight response hard limit exceeded".into(),
                });
            }
            let block: Value = serde_json::from_slice(&bytes)
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
            let page_id = action.request.resource.rsplit('/').next().ok_or_else(|| {
                KeyLeaseError::InvalidRequest {
                    reason: "missing Notion page id".into(),
                }
            })?;
            if block.pointer("/parent/page_id").and_then(Value::as_str) != Some(page_id) {
                return Err(KeyLeaseError::Denied {
                    reason: "Notion block is not a direct child of the enrolled page".into(),
                });
            }
            let expected = string_argument(&action.request.arguments, "content_digest")?;
            if response_hash(&block) != expected {
                return Err(KeyLeaseError::Denied {
                    reason: "Notion block changed since approval".into(),
                });
            }
        }
        if action.request.action == "google_sheets.values.update" {
            let id = action.request.resource.rsplit('/').next().ok_or_else(|| {
                KeyLeaseError::InvalidRequest {
                    reason: "missing spreadsheet id".into(),
                }
            })?;
            let range = encoded(string_argument(&action.request.arguments, "range")?);
            let response = self
                .client
                .get(format!(
                    "https://sheets.googleapis.com/v4/spreadsheets/{id}/values/{range}"
                ))
                .bearer_auth(credential.bearer_token())
                .header("accept", "application/json")
                .send()
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
            if !response.status().is_success() {
                return Err(KeyLeaseError::ConnectorUnavailable {
                    retryable: response.status().is_server_error(),
                });
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(KeyLeaseError::Denied {
                    reason: "preflight response hard limit exceeded".into(),
                });
            }
            let values: Value = serde_json::from_slice(&bytes)
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
            let expected = string_argument(&action.request.arguments, "expected_values_hash")?;
            if response_hash(&values) != expected {
                return Err(KeyLeaseError::Denied {
                    reason: "sheet values changed since approval".into(),
                });
            }
        }
        let request = build_http_request(&self.manifest.provider, action)?;
        let origin = self
            .manifest
            .fixed_https_origins
            .iter()
            .find(|o| request.path.starts_with(o.as_str()))
            .ok_or_else(|| KeyLeaseError::Denied {
                reason: "outbound origin not allowlisted".into(),
            })?;
        let mut builder = match request.method.as_str() {
            "GET" => self.client.get(&request.path),
            "POST" => self.client.post(&request.path),
            "PUT" => self.client.put(&request.path),
            "PATCH" => self.client.patch(&request.path),
            _ => {
                return Err(KeyLeaseError::Denied {
                    reason: "HTTP method not supported".into(),
                });
            }
        };
        let _ = origin;
        builder = builder
            .bearer_auth(credential.bearer_token())
            .header("accept", "application/json");
        if self.manifest.provider == "github" {
            builder = builder
                .header("user-agent", "KeyLease/0.1")
                .header("x-github-api-version", "2022-11-28");
        }
        if self.manifest.provider == "notion" {
            builder = builder.header("notion-version", "2025-09-03");
        }
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }
        let response = builder
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(KeyLeaseError::Denied {
                reason: "upstream response hard limit exceeded".into(),
            });
        }
        if !status.is_success() {
            return Err(KeyLeaseError::ConnectorUnavailable {
                retryable: status.as_u16() == 429 || status.is_server_error(),
            });
        }
        let body: Value = if action.request.action == "google_drive.file.export_text" {
            Value::String(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?,
            )
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?
        };
        let (item_count, cell_count) = response_counts(&action.request.action, &body);
        let revision = body
            .get("revisionId")
            .and_then(Value::as_str)
            .or_else(|| {
                body.pointer("/writeControl/requiredRevisionId")
                    .and_then(Value::as_str)
            })
            .map_or_else(|| response_hash(&body), str::to_owned);
        Ok(ActionResponse {
            provider: self.manifest.provider.clone(),
            connection_id: action.request.connection_id.clone(),
            canonical_resource: response_resource(action, &body)?,
            revision: Some(revision),
            untrusted_content: true,
            item_count,
            cell_count,
            body,
        })
    }
    async fn test_connection(&self, credential: &ConnectorCredential) -> Result<()> {
        if credential.bearer_token().is_empty() {
            return Err(KeyLeaseError::Denied {
                reason: "missing credential".into(),
            });
        }
        let (method, url, body) = match self.manifest.provider.as_str() {
            "google_workspace" => (
                "GET",
                "https://www.googleapis.com/drive/v3/about?fields=user",
                None,
            ),
            "github" => ("GET", "https://api.github.com/user", None),
            "linear" => (
                "POST",
                "https://api.linear.app/graphql",
                Some(json!({"query":"query { viewer { id } }"})),
            ),
            "notion" => ("GET", "https://api.notion.com/v1/users/me", None),
            _ => {
                return Err(KeyLeaseError::Denied {
                    reason: "unknown provider".into(),
                });
            }
        };
        let mut request = if method == "GET" {
            self.client.get(url)
        } else {
            self.client.post(url)
        }
        .bearer_auth(credential.bearer_token())
        .header("accept", "application/json");
        if self.manifest.provider == "github" {
            request = request.header("user-agent", "KeyLease/0.1");
        }
        if self.manifest.provider == "notion" {
            request = request.header("notion-version", "2025-09-03");
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(KeyLeaseError::Denied {
                reason: "connection health check was rejected".into(),
            })
        }
    }
    async fn refresh(
        &self,
        credential: &ConnectorCredential,
    ) -> Result<Option<ConnectorCredential>> {
        let mut oauth = match credential.oauth() {
            Some(value) => value,
            None => return Ok(None),
        };
        let refresh_token = oauth
            .refresh_token
            .clone()
            .ok_or_else(|| KeyLeaseError::Denied {
                reason: "connection has no refresh token".into(),
            })?;
        let client_id = oauth
            .client_id
            .clone()
            .ok_or_else(|| KeyLeaseError::Denied {
                reason: "connection has no OAuth client ID".into(),
            })?;
        let endpoint = match self.manifest.provider.as_str() {
            "google_workspace" => "https://oauth2.googleapis.com/token",
            "github" => "https://github.com/login/oauth/access_token",
            "linear" => "https://api.linear.app/oauth/token",
            "notion" => return Ok(None),
            _ => {
                return Err(KeyLeaseError::Denied {
                    reason: "unknown provider".into(),
                });
            }
        };
        let mut form = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];
        if let Some(secret) = oauth.client_secret.clone() {
            form.push(("client_secret", secret));
        }
        let response = self
            .client
            .post(endpoint)
            .header("accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        if !status.is_success() {
            return Err(KeyLeaseError::Denied {
                reason: "OAuth refresh was rejected".into(),
            });
        }
        oauth.access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or(KeyLeaseError::ConnectorUnavailable { retryable: false })?
            .into();
        if let Some(value) = body.get("refresh_token").and_then(Value::as_str) {
            oauth.refresh_token = Some(value.into());
        }
        oauth.expires_at = body
            .get("expires_in")
            .and_then(Value::as_i64)
            .map(|seconds| chrono::Utc::now() + chrono::Duration::seconds(seconds));
        let serialized = serde_json::to_string(&oauth)
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
        Ok(Some(ConnectorCredential::new(serialized)))
    }
    async fn revoke(&self, credential: &ConnectorCredential) -> Result<()> {
        if self.manifest.provider != "google_workspace" {
            return Ok(());
        }
        let token = credential.bearer_token();
        let response = self
            .client
            .post("https://oauth2.googleapis.com/revoke")
            .form(&[("token", token.as_ref())])
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(KeyLeaseError::Denied {
                reason: "provider revoke was rejected".into(),
            })
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    body: Option<Value>,
}
fn is_virtual_collection_action(request: &ActionRequest) -> bool {
    matches!(
        (request.action.as_str(), request.resource.as_str()),
        ("google_drive.file.list_authorized", "google:file")
            | ("notion.page.search_authorized", "notion:page")
    )
}
fn response_resource(action: &CanonicalAction, body: &Value) -> Result<String> {
    let created = match action.request.action.as_str() {
        "google_docs.document.create" | "google_sheets.spreadsheet.create" => {
            body.get("id").and_then(Value::as_str)
        }
        "notion.page.create" => body.get("id").and_then(Value::as_str),
        _ => return Ok(action.request.resource.clone()),
    }
    .ok_or(KeyLeaseError::ConnectorUnavailable { retryable: false })?;
    let prefix = match action.request.action.as_str() {
        "google_docs.document.create" => "google:document",
        "google_sheets.spreadsheet.create" => "google:spreadsheet",
        "notion.page.create" => "notion:page",
        _ => unreachable!("create action matched above"),
    };
    canonical_resource(&format!("{prefix}/{created}"))
}
fn is_google_sheet_range_action(action: &str) -> bool {
    matches!(
        action,
        "google_sheets.values.read"
            | "google_sheets.values.batch_read"
            | "google_sheets.rows.append"
            | "google_sheets.values.update"
    )
}
async fn validate_google_sheet_binding(
    client: &reqwest::Client,
    action: &CanonicalAction,
    credential: &ConnectorCredential,
) -> Result<()> {
    let spreadsheet_id = action.request.resource.rsplit('/').next().ok_or_else(|| {
        KeyLeaseError::InvalidRequest {
            reason: "missing spreadsheet id".into(),
        }
    })?;
    let response = client
        .get(format!(
            "https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}?fields=sheets.properties(sheetId,title)"
        ))
        .bearer_auth(credential.bearer_token())
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    if !response.status().is_success() {
        return Err(KeyLeaseError::ConnectorUnavailable {
            retryable: response.status().is_server_error(),
        });
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(KeyLeaseError::Denied {
            reason: "sheet metadata response hard limit exceeded".into(),
        });
    }
    let metadata: Value = serde_json::from_slice(&bytes)
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: false })?;
    validate_sheet_binding(action, &metadata)
}
fn validate_sheet_binding(action: &CanonicalAction, metadata: &Value) -> Result<()> {
    let sheet_id = number_argument(&action.request.arguments, "sheet_id")?;
    let title = metadata
        .get("sheets")
        .and_then(Value::as_array)
        .and_then(|sheets| {
            sheets.iter().find_map(|sheet| {
                let properties = sheet.get("properties")?;
                (properties.get("sheetId")?.as_u64()? == sheet_id)
                    .then(|| properties.get("title")?.as_str().map(str::to_owned))?
            })
        })
        .ok_or_else(|| KeyLeaseError::Denied {
            reason: "sheet_id is not present in the authorized spreadsheet".into(),
        })?;
    let ranges = action
        .request
        .arguments
        .get("ranges")
        .and_then(Value::as_array)
        .map(|ranges| ranges.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .or_else(|| {
            action
                .request
                .arguments
                .get("range")
                .and_then(Value::as_str)
                .map(|range| vec![range])
        })
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "sheet action requires a range".into(),
        })?;
    if ranges
        .iter()
        .any(|range| a1_sheet_name(range).as_deref() != Ok(title.as_str()))
    {
        return Err(KeyLeaseError::Denied {
            reason: "A1 range sheet name does not match the stable sheet_id".into(),
        });
    }
    Ok(())
}
fn build_http_request(provider: &str, action: &CanonicalAction) -> Result<HttpRequest> {
    let id = action.request.resource.rsplit('/').next().ok_or_else(|| {
        KeyLeaseError::InvalidRequest {
            reason: "missing resource id".into(),
        }
    })?;
    let arguments = &action.request.arguments;
    let (method, path, body) = match (provider, action.request.action.as_str()) {
        ("google_workspace", "google_drive.file.get_metadata") => (
            "GET",
            format!(
                "https://www.googleapis.com/drive/v3/files/{id}?fields=id,name,mimeType,modifiedTime"
            ),
            None,
        ),
        ("google_workspace", "google_drive.file.export_text") => (
            "GET",
            format!("https://www.googleapis.com/drive/v3/files/{id}/export?mimeType=text%2Fplain"),
            None,
        ),
        ("google_workspace", "google_docs.document.get") => (
            "GET",
            format!("https://docs.googleapis.com/v1/documents/{id}"),
            None,
        ),
        ("google_workspace", "google_docs.document.create") => (
            "POST",
            "https://www.googleapis.com/drive/v3/files?fields=id,name,mimeType".into(),
            Some(json!({
                "name":string_argument(arguments,"title")?,
                "mimeType":"application/vnd.google-apps.document",
                "parents":[id]
            })),
        ),
        ("google_workspace", "google_docs.document.append") => (
            "POST",
            format!("https://docs.googleapis.com/v1/documents/{id}:batchUpdate"),
            Some(
                json!({"requests":[{"insertText":{"endOfSegmentLocation":{},"text":string_argument(arguments,"text")?}}],"writeControl":optional_string_object(arguments,"expected_revision","requiredRevisionId")}),
            ),
        ),
        ("google_workspace", "google_docs.document.update") => (
            "POST",
            format!("https://docs.googleapis.com/v1/documents/{id}:batchUpdate"),
            Some(
                json!({"requests":[{"deleteContentRange":{"range":{"startIndex":number_argument(arguments,"start_index")?,"endIndex":number_argument(arguments,"end_index")?}}},{"insertText":{"location":{"index":number_argument(arguments,"start_index")?},"text":string_argument(arguments,"text")?}}],"writeControl":{"requiredRevisionId":string_argument(arguments,"expected_revision")?}}),
            ),
        ),
        ("google_workspace", "google_sheets.spreadsheet.get_metadata") => (
            "GET",
            format!(
                "https://sheets.googleapis.com/v4/spreadsheets/{id}?fields=spreadsheetId,properties.title,sheets.properties"
            ),
            None,
        ),
        ("google_workspace", "google_sheets.values.read") => {
            let range = encoded(string_argument(arguments, "range")?);
            (
                "GET",
                format!("https://sheets.googleapis.com/v4/spreadsheets/{id}/values/{range}"),
                None,
            )
        }
        ("google_workspace", "google_sheets.values.batch_read") => {
            let ranges = arguments
                .get("ranges")
                .and_then(Value::as_array)
                .ok_or_else(|| KeyLeaseError::InvalidRequest {
                    reason: "ranges must be an array".into(),
                })?;
            let query = ranges
                .iter()
                .map(|range| {
                    range
                        .as_str()
                        .ok_or_else(|| KeyLeaseError::InvalidRequest {
                            reason: "range must be a string".into(),
                        })
                        .map(|range| format!("ranges={}", encoded(range)))
                })
                .collect::<Result<Vec<_>>>()?
                .join("&");
            (
                "GET",
                format!(
                    "https://sheets.googleapis.com/v4/spreadsheets/{id}/values:batchGet?{query}"
                ),
                None,
            )
        }
        ("google_workspace", "google_sheets.rows.append") => {
            let range = encoded(string_argument(arguments, "range")?);
            (
                "POST",
                format!(
                    "https://sheets.googleapis.com/v4/spreadsheets/{id}/values/{range}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS"
                ),
                Some(
                    json!({"range":string_argument(arguments,"range")?,"majorDimension":"ROWS","values":arguments["values"]}),
                ),
            )
        }
        ("google_workspace", "google_sheets.values.update") => {
            let range = encoded(string_argument(arguments, "range")?);
            (
                "PUT",
                format!(
                    "https://sheets.googleapis.com/v4/spreadsheets/{id}/values/{range}?valueInputOption=RAW"
                ),
                Some(
                    json!({"range":string_argument(arguments,"range")?,"majorDimension":"ROWS","values":arguments["values"]}),
                ),
            )
        }
        ("google_workspace", "google_sheets.spreadsheet.create") => (
            "POST",
            "https://www.googleapis.com/drive/v3/files?fields=id,name,mimeType".into(),
            Some(json!({
                "name":string_argument(arguments,"title")?,
                "mimeType":"application/vnd.google-apps.spreadsheet",
                "parents":[id]
            })),
        ),
        ("github", "github.repository.get_metadata") => (
            "GET",
            format!("https://api.github.com/repositories/{id}"),
            None,
        ),
        ("github", "github.issue.list") => (
            "GET",
            format!("https://api.github.com/repositories/{id}/issues"),
            None,
        ),
        ("github", "github.issue.get") => (
            "GET",
            format!(
                "https://api.github.com/repositories/{id}/issues/{}",
                integer_argument(arguments, "number")?
            ),
            None,
        ),
        ("github", "github.issue.create") => (
            "POST",
            format!("https://api.github.com/repositories/{id}/issues"),
            Some(copy_arguments(arguments, &["title", "body", "labels"])),
        ),
        ("github", "github.issue.comment") => (
            "POST",
            format!(
                "https://api.github.com/repositories/{id}/issues/{}/comments",
                integer_argument(arguments, "number")?
            ),
            Some(copy_arguments(arguments, &["body"])),
        ),
        ("github", "github.pull_request.list") => (
            "GET",
            format!("https://api.github.com/repositories/{id}/pulls"),
            None,
        ),
        ("github", "github.pull_request.get") => (
            "GET",
            format!(
                "https://api.github.com/repositories/{id}/pulls/{}",
                integer_argument(arguments, "number")?
            ),
            None,
        ),
        ("github", "github.pull_request.create_draft") => (
            "POST",
            format!("https://api.github.com/repositories/{id}/pulls"),
            Some(
                json!({"title":string_argument(arguments,"title")?,"body":arguments.get("body"),"base":string_argument(arguments,"base")?,"head":string_argument(arguments,"head")?,"draft":true}),
            ),
        ),
        ("github", "github.pull_request.comment") => (
            "POST",
            format!(
                "https://api.github.com/repositories/{id}/issues/{}/comments",
                integer_argument(arguments, "number")?
            ),
            Some(copy_arguments(arguments, &["body"])),
        ),
        ("github", "github.checks.read") => (
            "GET",
            format!(
                "https://api.github.com/repositories/{id}/commits/{}/check-runs",
                encoded(string_argument(arguments, "ref")?)
            ),
            None,
        ),
        ("linear", action_name) => (
            "POST",
            "https://api.linear.app/graphql".into(),
            Some(linear_payload(action_name, arguments, id)?),
        ),
        ("notion", "notion.page.search_authorized") => (
            "POST",
            "https://api.notion.com/v1/search".into(),
            Some(json!({"filter":{"property":"object","value":"page"},"page_size":100})),
        ),
        ("notion", "notion.page.get_markdown") => (
            "GET",
            format!("https://api.notion.com/v1/blocks/{id}/children?page_size=100"),
            None,
        ),
        ("notion", "notion.page.create") => (
            "POST",
            "https://api.notion.com/v1/pages".into(),
            Some(
                json!({"parent":{"page_id":string_argument(arguments,"parent_id")?},"properties":{"title":{"title":[{"text":{"content":"KeyLease page"}}]}},"children":markdown_blocks(string_argument(arguments,"markdown")?)}),
            ),
        ),
        ("notion", "notion.page.append_markdown") => (
            "PATCH",
            format!("https://api.notion.com/v1/blocks/{id}/children"),
            Some(json!({"children":markdown_blocks(string_argument(arguments,"markdown")?)})),
        ),
        ("notion", "notion.page.update_markdown") => {
            let block_id = encoded(string_argument(arguments, "block_id")?);
            let markdown = string_argument(arguments, "markdown")?;
            (
                "PATCH",
                format!("https://api.notion.com/v1/blocks/{block_id}"),
                Some(
                    json!({"paragraph":{"rich_text":[{"type":"text","text":{"content":markdown}}]}}),
                ),
            )
        }
        _ => {
            return Err(KeyLeaseError::Denied {
                reason: "action has no built-in HTTP mapping".into(),
            });
        }
    };
    Ok(HttpRequest {
        method: method.into(),
        path,
        body,
    })
}

fn string_argument<'a>(arguments: &'a Value, name: &str) -> Result<&'a str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: format!("missing string argument: {name}"),
        })
}
fn validate_digest_argument(arguments: &Value, name: &str) -> Result<()> {
    let value = string_argument(arguments, name)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("{name} must be a 64-character SHA-256 hex digest"),
        });
    }
    Ok(())
}
fn number_argument(arguments: &Value, name: &str) -> Result<u64> {
    arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: format!("missing integer argument: {name}"),
        })
}
fn integer_argument(arguments: &Value, name: &str) -> Result<u64> {
    number_argument(arguments, name)
}
fn encoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
fn optional_string_object(arguments: &Value, name: &str, key: &str) -> Value {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map_or(Value::Object(Map::new()), |value| json!({key:value}))
}
fn copy_arguments(arguments: &Value, names: &[&str]) -> Value {
    let mut output = Map::new();
    for name in names {
        if let Some(value) = arguments.get(*name) {
            output.insert((*name).into(), value.clone());
        }
    }
    Value::Object(output)
}
fn markdown_blocks(markdown: &str) -> Vec<Value> {
    markdown.lines().take(1000).map(|line|json!({"object":"block","type":"paragraph","paragraph":{"rich_text":[{"type":"text","text":{"content":line}}]}})).collect()
}
pub fn a1_cell_count(range: &str) -> Result<u64> {
    let coordinates = range.rsplit('!').next().unwrap_or(range);
    let mut parts = coordinates.split(':');
    let start = parse_a1(parts.next().unwrap_or_default())?;
    let end = parse_a1(parts.next().unwrap_or(coordinates))?;
    if parts.next().is_some() || end.0 < start.0 || end.1 < start.1 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "range must be a bounded rectangular A1 range".into(),
        });
    }
    Ok((end.0 - start.0 + 1).saturating_mul(end.1 - start.1 + 1))
}
fn a1_sheet_name(range: &str) -> Result<String> {
    let (sheet, _) = range
        .rsplit_once('!')
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "A1 range must explicitly name its sheet".into(),
        })?;
    if sheet.is_empty() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "A1 range has an empty sheet name".into(),
        });
    }
    if sheet.starts_with('\'') || sheet.ends_with('\'') {
        if !(sheet.starts_with('\'') && sheet.ends_with('\'') && sheet.len() >= 2) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "A1 range has invalid sheet quoting".into(),
            });
        }
        return Ok(sheet[1..sheet.len() - 1].replace("''", "'"));
    }
    Ok(sheet.to_owned())
}
fn parse_a1(value: &str) -> Result<(u64, u64)> {
    let clean = value.replace('$', "");
    let split = clean
        .find(|character: char| character.is_ascii_digit())
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "range must include row numbers".into(),
        })?;
    let (letters, digits) = clean.split_at(split);
    if letters.is_empty()
        || !letters.chars().all(|c| c.is_ascii_alphabetic())
        || digits.parse::<u64>().ok().filter(|v| *v > 0).is_none()
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "invalid A1 range".into(),
        });
    }
    let column = letters
        .to_ascii_uppercase()
        .bytes()
        .fold(0_u64, |value, c| {
            value
                .saturating_mul(26)
                .saturating_add((c - b'A' + 1) as u64)
        });
    Ok((column, digits.parse().expect("validated digits")))
}
fn response_counts(action: &str, body: &Value) -> (Option<u64>, Option<u64>) {
    if action.starts_with("google_sheets.values.") {
        let ranges: Vec<&Value> = body
            .get("valueRanges")
            .and_then(Value::as_array)
            .map_or_else(|| vec![body], |ranges| ranges.iter().collect());
        let mut saw_values = false;
        let (rows, cells) = ranges.iter().fold((0_u64, 0_u64), |counts, range| {
            let Some(values) = range.get("values").and_then(Value::as_array) else {
                return counts;
            };
            saw_values = true;
            (
                counts.0.saturating_add(values.len() as u64),
                counts.1.saturating_add(
                    values
                        .iter()
                        .map(|row| row.as_array().map_or(0, |cells| cells.len() as u64))
                        .sum(),
                ),
            )
        });
        if saw_values {
            (Some(rows), Some(cells))
        } else {
            (None, None)
        }
    } else {
        let items = body
            .as_array()
            .map(|items| items.len() as u64)
            .or_else(|| {
                body.get("items")
                    .and_then(Value::as_array)
                    .map(|items| items.len() as u64)
            })
            .or_else(|| {
                body.get("results")
                    .and_then(Value::as_array)
                    .map(|items| items.len() as u64)
            })
            .or_else(|| {
                body.get("nodes")
                    .and_then(Value::as_array)
                    .map(|items| items.len() as u64)
            })
            .or_else(|| {
                body.pointer("/data/issues/nodes")
                    .and_then(Value::as_array)
                    .map(|items| items.len() as u64)
            });
        (items, None)
    }
}
fn linear_payload(action: &str, arguments: &Value, team_id: &str) -> Result<Value> {
    let payload = match action {
        "linear.issue.list" => {
            json!({"query":"query($team:String!){issues(filter:{team:{id:{eq:$team}}}){nodes{id title description}}}","variables":{"team":team_id}})
        }
        "linear.issue.get" => {
            json!({"query":"query($id:String!){issue(id:$id){id title description}}","variables":{"id":string_argument(arguments,"issue_id")?}})
        }
        "linear.issue.create" => {
            json!({"query":"mutation($input:IssueCreateInput!){issueCreate(input:$input){success issue{id}}}","variables":{"input":{"teamId":team_id,"title":string_argument(arguments,"title")?,"description":arguments.get("body")}}})
        }
        "linear.comment.create" => {
            json!({"query":"mutation($input:CommentCreateInput!){commentCreate(input:$input){success comment{id}}}","variables":{"input":{"issueId":string_argument(arguments,"issue_id")?,"body":string_argument(arguments,"body")?}}})
        }
        _ => {
            return Err(KeyLeaseError::Denied {
                reason: "unknown Linear action".into(),
            });
        }
    };
    Ok(payload)
}

pub fn google_manifest() -> ConnectorManifest {
    ConnectorManifest {
        provider: "google_workspace".into(),
        version: "1".into(),
        authentication_methods: vec!["oauth_pkce".into()],
        fixed_https_origins: vec![
            "https://www.googleapis.com".into(),
            "https://docs.googleapis.com".into(),
            "https://sheets.googleapis.com".into(),
        ],
        actions: vec![
            spec(
                "google_drive.file.list_authorized",
                "google:file",
                RiskTier::R0,
                &[],
                &[],
                ContentAccess::Metadata,
                true,
            ),
            spec(
                "google_drive.file.get_metadata",
                "google:file",
                RiskTier::R0,
                &[],
                &[],
                ContentAccess::Metadata,
                true,
            ),
            spec(
                "google_drive.file.export_text",
                "google:file",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "google_docs.document.get",
                "google:document",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "google_docs.document.create",
                "google:folder",
                RiskTier::R2,
                &[("title", JsonType::String)],
                &["title"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "google_docs.document.append",
                "google:document",
                RiskTier::R2,
                &[
                    ("text", JsonType::String),
                    ("expected_revision", JsonType::String),
                ],
                &["text"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "google_docs.document.update",
                "google:document",
                RiskTier::R3,
                &[
                    ("text", JsonType::String),
                    ("start_index", JsonType::Number),
                    ("end_index", JsonType::Number),
                    ("expected_revision", JsonType::String),
                ],
                &["text", "start_index", "end_index", "expected_revision"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "google_sheets.spreadsheet.get_metadata",
                "google:spreadsheet",
                RiskTier::R0,
                &[],
                &[],
                ContentAccess::Metadata,
                true,
            ),
            spec(
                "google_sheets.values.read",
                "google:spreadsheet",
                RiskTier::R1,
                &[("sheet_id", JsonType::Number), ("range", JsonType::String)],
                &["sheet_id", "range"],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "google_sheets.values.batch_read",
                "google:spreadsheet",
                RiskTier::R1,
                &[("sheet_id", JsonType::Number), ("ranges", JsonType::Array)],
                &["sheet_id", "ranges"],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "google_sheets.rows.append",
                "google:spreadsheet",
                RiskTier::R2,
                &[
                    ("sheet_id", JsonType::Number),
                    ("range", JsonType::String),
                    ("values", JsonType::Array),
                    ("value_input_option", JsonType::String),
                ],
                &["sheet_id", "range", "values"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "google_sheets.values.update",
                "google:spreadsheet",
                RiskTier::R3,
                &[
                    ("sheet_id", JsonType::Number),
                    ("range", JsonType::String),
                    ("values", JsonType::Array),
                    ("expected_values_hash", JsonType::String),
                    ("value_input_option", JsonType::String),
                ],
                &["sheet_id", "range", "values", "expected_values_hash"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "google_sheets.spreadsheet.create",
                "google:folder",
                RiskTier::R2,
                &[("title", JsonType::String)],
                &["title"],
                ContentAccess::Metadata,
                false,
            ),
        ],
    }
}
pub fn github_manifest() -> ConnectorManifest {
    ConnectorManifest {
        provider: "github".into(),
        version: "1-beta".into(),
        authentication_methods: vec!["github_app".into()],
        fixed_https_origins: vec!["https://api.github.com".into()],
        actions: vec![
            spec(
                "github.repository.get_metadata",
                "github:repository",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::Metadata,
                true,
            ),
            spec(
                "github.issue.list",
                "github:repository",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "github.issue.get",
                "github:repository",
                RiskTier::R1,
                &[("number", JsonType::Number)],
                &["number"],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "github.issue.create",
                "github:repository",
                RiskTier::R2,
                &[
                    ("title", JsonType::String),
                    ("body", JsonType::String),
                    ("labels", JsonType::Array),
                ],
                &["title"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "github.issue.comment",
                "github:repository",
                RiskTier::R2,
                &[("number", JsonType::Number), ("body", JsonType::String)],
                &["number", "body"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "github.pull_request.list",
                "github:repository",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "github.pull_request.get",
                "github:repository",
                RiskTier::R1,
                &[("number", JsonType::Number)],
                &["number"],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "github.pull_request.create_draft",
                "github:repository",
                RiskTier::R2,
                &[
                    ("title", JsonType::String),
                    ("body", JsonType::String),
                    ("base", JsonType::String),
                    ("head", JsonType::String),
                ],
                &["title", "base", "head"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "github.pull_request.comment",
                "github:repository",
                RiskTier::R2,
                &[("number", JsonType::Number), ("body", JsonType::String)],
                &["number", "body"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "github.checks.read",
                "github:repository",
                RiskTier::R1,
                &[("ref", JsonType::String)],
                &["ref"],
                ContentAccess::BoundedContent,
                true,
            ),
        ],
    }
}
pub fn linear_manifest() -> ConnectorManifest {
    ConnectorManifest {
        provider: "linear".into(),
        version: "1-beta".into(),
        authentication_methods: vec!["oauth_pkce_actor_app".into()],
        fixed_https_origins: vec!["https://api.linear.app".into()],
        actions: vec![
            spec(
                "linear.issue.list",
                "linear:team",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "linear.issue.get",
                "linear:team",
                RiskTier::R1,
                &[("issue_id", JsonType::String)],
                &["issue_id"],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "linear.issue.create",
                "linear:team",
                RiskTier::R2,
                &[("title", JsonType::String), ("body", JsonType::String)],
                &["title"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "linear.comment.create",
                "linear:team",
                RiskTier::R2,
                &[("issue_id", JsonType::String), ("body", JsonType::String)],
                &["issue_id", "body"],
                ContentAccess::Metadata,
                false,
            ),
        ],
    }
}
pub fn notion_manifest() -> ConnectorManifest {
    ConnectorManifest {
        provider: "notion".into(),
        version: "1-beta".into(),
        authentication_methods: vec!["internal_token".into()],
        fixed_https_origins: vec!["https://api.notion.com".into()],
        actions: vec![
            spec(
                "notion.page.search_authorized",
                "notion:page",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::Metadata,
                true,
            ),
            spec(
                "notion.page.get_markdown",
                "notion:page",
                RiskTier::R1,
                &[],
                &[],
                ContentAccess::BoundedContent,
                true,
            ),
            spec(
                "notion.page.create",
                "notion:page",
                RiskTier::R2,
                &[
                    ("parent_id", JsonType::String),
                    ("markdown", JsonType::String),
                ],
                &["parent_id", "markdown"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "notion.page.append_markdown",
                "notion:page",
                RiskTier::R2,
                &[("markdown", JsonType::String)],
                &["markdown"],
                ContentAccess::Metadata,
                false,
            ),
            spec(
                "notion.page.update_markdown",
                "notion:page",
                RiskTier::R3,
                &[
                    ("block_id", JsonType::String),
                    ("markdown", JsonType::String),
                    ("content_digest", JsonType::String),
                ],
                &["block_id", "markdown", "content_digest"],
                ContentAccess::Metadata,
                false,
            ),
        ],
    }
}

fn spec(
    name: &str,
    prefix: &str,
    risk: RiskTier,
    allowed: &[(&str, JsonType)],
    required_fields: &[&str],
    content_access: ContentAccess,
    idempotent: bool,
) -> ActionSpec {
    ActionSpec {
        name: name.into(),
        resource_prefix: prefix.into(),
        risk,
        allowed_fields: fields(allowed),
        required_fields: required(required_fields),
        content_access,
        default_budget: DataBudget {
            max_items: Some(100),
            max_cells: Some(10_000),
            max_response_bytes: Some(1_048_576),
            max_rows_changed: Some(1_000),
            max_concurrent: Some(1),
        },
        idempotent,
    }
}

pub fn response_hash(value: &Value) -> String {
    Sha256::digest(serde_json::to_vec(value).unwrap_or_default())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylease_core::*;
    fn request(action: &str, args: Value) -> ActionRequest {
        ActionRequest {
            schema_version: 1,
            request_id: RequestId::new(),
            subject: ActorContext {
                agent_id: AgentId::new(),
                workload_id: None,
                human_principal: None,
                on_behalf_of: None,
                client_session_id: "s".into(),
            },
            task_id: None,
            connection_id: ConnectionId::new(),
            resource: "fake:resource/1".into(),
            action: action.into(),
            arguments: args,
            idempotency_key: "i".into(),
        }
    }
    #[tokio::test]
    async fn fake_denies_unknown_action_field_and_alias() {
        let c = FakeConnector::default();
        assert!(
            c.canonicalize(&request("fake.unknown", serde_json::json!({})))
                .await
                .is_err()
        );
        assert!(
            c.canonicalize(&request(
                "fake.resource.read",
                serde_json::json!({"secret":"x"})
            ))
            .await
            .is_err()
        );
        let mut r = request("fake.resource.read", serde_json::json!({}));
        r.resource = "fake:resource/../other".into();
        assert!(c.canonicalize(&r).await.is_err());
    }
    #[tokio::test]
    async fn fake_faults_and_redaction() {
        let c = FakeConnector::default();
        let credential = ConnectorCredential::new("fixture-secret".into());
        let action = c
            .canonicalize(&request("fake.resource.read", serde_json::json!({})))
            .await
            .unwrap();
        for failure in [
            FakeFailure::OAuthExpired,
            FakeFailure::OAuthDenied,
            FakeFailure::Revoked,
            FakeFailure::InvalidScope,
            FakeFailure::RateLimited,
            FakeFailure::Timeout,
            FakeFailure::PartialFailure,
            FakeFailure::SchemaDrift,
            FakeFailure::LeakSecret,
        ] {
            c.set_failure(failure);
            let error = format!("{:?}", c.execute(&action, &credential).await.unwrap_err());
            assert!(!error.contains("fixture-secret"));
        }
    }
    #[test]
    fn manifests_do_not_expose_forbidden_actions_or_formula_write() {
        for manifest in [
            google_manifest(),
            github_manifest(),
            linear_manifest(),
            notion_manifest(),
        ] {
            for action in manifest.actions {
                assert!(!action.name.contains("delete"));
                assert!(!action.name.contains("share"));
                assert!(!action.name.contains("permission"));
                assert!(!action.name.contains("formula"));
            }
        }
    }
    #[test]
    fn google_sheet_writes_are_raw_only() {
        let m = google_manifest();
        for action in m.actions.iter().filter(|a| {
            a.name == "google_sheets.rows.append" || a.name == "google_sheets.values.update"
        }) {
            assert!(action.allowed_fields.contains_key("value_input_option"));
        }
    }
    #[tokio::test]
    async fn google_canonicalization_defaults_raw_and_denies_formula_mode() {
        let connector = BuiltinConnector::google();
        let mut request = request("fake.resource.read", serde_json::json!({}));
        request.action = "google_sheets.rows.append".into();
        request.resource = "google:spreadsheet/file-id".into();
        request.arguments =
            serde_json::json!({"sheet_id":1,"range":"Data!A1:B2","values":[["=IMPORTXML(...) "]]});
        let canonical = connector.canonicalize(&request).await.unwrap();
        assert_eq!(canonical.request.arguments["value_input_option"], "RAW");
        request.arguments["value_input_option"] = Value::String("USER_ENTERED".into());
        assert!(connector.canonicalize(&request).await.is_err());
    }
    #[tokio::test]
    async fn beta_connectors_share_deny_by_default_resource_and_field_checks() {
        for connector in [
            BuiltinConnector::github(),
            BuiltinConnector::linear(),
            BuiltinConnector::notion(),
        ] {
            let manifest = connector.manifest();
            let spec = &manifest.actions[0];
            let mut candidate = request(&spec.name, serde_json::json!({"unknown":"must fail"}));
            candidate.resource = format!("{}/stable-id", spec.resource_prefix);
            assert!(connector.canonicalize(&candidate).await.is_err());
            candidate.arguments = Value::Object(Map::new());
            candidate.resource = "other:scope/stable-id".into();
            assert!(connector.canonicalize(&candidate).await.is_err());
        }
    }
    #[test]
    fn enrolled_provider_resources_are_exact_canonical_objects() {
        let fake = FakeConnector::default().manifest();
        assert_eq!(
            validate_enrolled_resource(&fake, "fake:resource/one").unwrap(),
            "fake:resource/one"
        );
        assert!(validate_enrolled_resource(&fake, "fake:resource/one/two").is_err());
        assert!(
            validate_enrolled_resource(&github_manifest(), "github:repository/acme/repo").is_err()
        );
        assert!(validate_enrolled_resource(&github_manifest(), "github:repository/42").is_ok());
    }
    #[tokio::test]
    async fn github_requires_stable_numeric_repository_id_and_action_fields() {
        let connector = BuiltinConnector::github();
        let mut candidate = request("github.issue.get", json!({"number": 7}));
        candidate.resource = "github:repository/owner-name-alias".into();
        assert!(connector.canonicalize(&candidate).await.is_err());

        candidate.resource = "github:repository/123456".into();
        assert!(connector.canonicalize(&candidate).await.is_ok());
        candidate.resource = "github:repository/123456/789".into();
        assert!(connector.canonicalize(&candidate).await.is_err());
        candidate.resource = "github:repository/123456".into();
        candidate.arguments = json!({});
        assert!(connector.canonicalize(&candidate).await.is_err());
    }
    #[tokio::test]
    async fn notion_update_requires_digest_and_encodes_block_identifier() {
        let connector = BuiltinConnector::notion();
        let mut candidate = request(
            "notion.page.update_markdown",
            json!({"block_id":"block/id", "markdown":"safe", "content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
        );
        candidate.resource = "notion:page/page-id".into();
        let canonical = connector.canonicalize(&candidate).await.unwrap();
        let http = build_http_request("notion", &canonical).unwrap();
        assert!(http.path.ends_with("/block%2Fid"));

        candidate.arguments = json!({"block_id":"block", "markdown":"safe"});
        assert!(connector.canonicalize(&candidate).await.is_err());
    }
    #[tokio::test]
    async fn collection_actions_and_created_ids_are_explicitly_scoped() {
        let google = BuiltinConnector::google();
        let mut document = request(
            "google_docs.document.create",
            json!({"title":"Created by KeyLease"}),
        );
        document.resource = "google:folder/folder-1".into();
        let document = google.canonicalize(&document).await.unwrap();
        assert_eq!(
            response_resource(&document, &json!({"id":"doc-123"})).unwrap(),
            "google:document/doc-123"
        );
        let document_http = build_http_request("google_workspace", &document).unwrap();
        assert_eq!(document_http.body.unwrap()["parents"][0], "folder-1");

        let mut spreadsheet = request(
            "google_sheets.spreadsheet.create",
            json!({"title":"Created by KeyLease"}),
        );
        spreadsheet.resource = "google:folder/folder-1".into();
        let spreadsheet = google.canonicalize(&spreadsheet).await.unwrap();
        assert_eq!(
            response_resource(&spreadsheet, &json!({"id":"sheet-123"})).unwrap(),
            "google:spreadsheet/sheet-123"
        );

        let notion = BuiltinConnector::notion();
        let mut listing = request("notion.page.search_authorized", json!({}));
        listing.resource = "notion:page".into();
        assert!(notion.canonicalize(&listing).await.is_ok());

        let mut page = request(
            "notion.page.create",
            json!({"parent_id":"parent-1","markdown":"content"}),
        );
        page.resource = "notion:page/parent-2".into();
        assert!(notion.canonicalize(&page).await.is_err());
        page.resource = "notion:page/parent-1".into();
        let page = notion.canonicalize(&page).await.unwrap();
        assert_eq!(
            response_resource(&page, &json!({"id":"new-page"})).unwrap(),
            "notion:page/new-page"
        );
    }
    #[tokio::test]
    async fn sheets_request_builder_never_emits_structural_batch_update_or_user_entered() {
        let connector = BuiltinConnector::google();
        let mut request = request("fake.resource.read", Value::Null);
        request.action = "google_sheets.rows.append".into();
        request.resource = "google:spreadsheet/file_id".into();
        request.arguments = json!({"sheet_id":42,"range":"Data!A1:B2","values":[["=1+1","safe"]]});
        let action = connector.canonicalize(&request).await.unwrap();
        let http = build_http_request("google_workspace", &action).unwrap();
        assert!(http.path.contains("valueInputOption=RAW"));
        assert!(!http.path.contains("batchUpdate"));
        assert!(!http.path.contains("USER_ENTERED"));
        assert_eq!(http.body.unwrap()["values"][0][0], "=1+1");
        assert!(
            validate_sheet_binding(
                &action,
                &json!({"sheets":[{"properties":{"sheetId":42,"title":"Data"}}]})
            )
            .is_ok()
        );
        assert!(
            validate_sheet_binding(
                &action,
                &json!({"sheets":[{"properties":{"sheetId":42,"title":"Other"}}]})
            )
            .is_err()
        );
    }
    #[test]
    fn a1_ranges_must_be_concrete_and_bounded() {
        assert_eq!(a1_cell_count("Data!A1:C10").unwrap(), 30);
        assert!(a1_cell_count("A:C").is_err());
        assert!(a1_cell_count("1:10").is_err());
        assert!(a1_cell_count("B2:A1").is_err());
    }
    #[test]
    fn structured_oauth_credentials_are_redacted_and_only_expose_access_token() {
        let raw = json!({"access_token":"access-secret","refresh_token":"refresh-secret","client_id":"desktop-id","client_secret":null,"expires_at":null,"scopes":["https://www.googleapis.com/auth/drive.file"]}).to_string();
        validate_connection_credential("google_workspace", &raw).unwrap();
        let credential = ConnectorCredential::new(raw);
        assert_eq!(credential.bearer_token(), "access-secret");
        assert!(!format!("{credential:?}").contains("access-secret"));
        assert!(!format!("{:?}", credential.oauth().unwrap()).contains("refresh-secret"));
        assert!(validate_connection_credential(
            "google_workspace",
            &json!({"access_token":"token","refresh_token":null,"client_id":"id","client_secret":null,"expires_at":null,"scopes":["https://www.googleapis.com/auth/drive"]}).to_string()
        )
        .is_err());
    }
    #[test]
    fn response_budget_marks_external_data_untrusted() {
        let response = ActionResponse {
            provider: "fake".into(),
            connection_id: ConnectionId::new(),
            canonical_resource: "fake:resource/1".into(),
            revision: None,
            untrusted_content: false,
            item_count: Some(2),
            cell_count: None,
            body: serde_json::json!([1, 2]),
        };
        assert!(
            enforce_response_budget(
                response.clone(),
                &DataBudget {
                    max_items: Some(1),
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(
            enforce_response_budget(
                response,
                &DataBudget {
                    max_items: Some(2),
                    max_response_bytes: Some(100),
                    ..Default::default()
                }
            )
            .unwrap()
            .untrusted_content
        );
    }
    #[test]
    fn batch_sheet_and_provider_response_counts_are_bounded() {
        assert_eq!(
            response_counts(
                "google_sheets.values.batch_read",
                &json!({"valueRanges":[{"values":[[1,2],[3]]},{"values":[[4]]}]})
            ),
            (Some(3), Some(4))
        );
        assert_eq!(
            response_counts("notion.page.search_authorized", &json!({"results":[1,2]})).0,
            Some(2)
        );
        assert_eq!(
            response_counts(
                "linear.issue.list",
                &json!({"data":{"issues":{"nodes":[1,2,3]}}})
            )
            .0,
            Some(3)
        );
    }
}
