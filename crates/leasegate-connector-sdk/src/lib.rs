//! Phase 4 connector SDK contracts, static conformance checks and signed
//! package metadata. Registry publication never grants runtime authority.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keylease_core::{
    ConnectorPublisherId, KeyLeaseError, OrganizationId, ProjectId, Result, RiskTier,
};
use leasegate_connectors::{
    CONNECTOR_MANIFEST_VERSION, ConnectorManifest, ConnectorRuntime, JsonType,
};
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use url::Url;
use zeroize::Zeroize;

pub const CONNECTOR_PACKAGE_VERSION: u32 = 1;
const SIGNATURE_ALGORITHM: &str = "ed25519-jcs-rfc8785-v1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackagePayload {
    pub schema_version: u32,
    pub manifest: ConnectorManifest,
    /// Digest of the immutable executable/archive. A built-in connector uses
    /// its reproducible build artifact digest.
    pub artifact_digest_sha256: String,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedConnectorPackage {
    pub algorithm: String,
    pub publisher_id: String,
    pub payload: ConnectorPackagePayload,
    pub payload_digest_sha256: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRegistryStatus {
    Published,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorRegistryEntry {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub publisher_id: ConnectorPublisherId,
    pub provider: String,
    pub connector_version: String,
    pub manifest_digest_sha256: String,
    pub artifact_digest_sha256: String,
    pub status: ConnectorRegistryStatus,
    pub package: SignedConnectorPackage,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConformanceCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReport {
    pub provider: String,
    pub connector_version: String,
    pub manifest_digest_sha256: String,
    pub passed: bool,
    pub checks: Vec<ConformanceCheck>,
}

pub struct ConnectorPackageSigner {
    publisher_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for ConnectorPackageSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorPackageSigner")
            .field("publisher_id", &self.publisher_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ConnectorPackageSigner {
    pub fn generate(publisher_id: impl Into<String>) -> Result<Self> {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let signer = Self::from_bytes(publisher_id, &bytes);
        bytes.zeroize();
        signer
    }

    pub fn from_bytes(publisher_id: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let publisher_id = publisher_id.into();
        validate_identifier(&publisher_id, "publisher id")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "Ed25519 connector signing key must contain 32 bytes".into(),
            })?;
        Ok(Self {
            publisher_id,
            key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn verifying_key_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, payload: ConnectorPackagePayload) -> Result<SignedConnectorPackage> {
        validate_package_payload(&payload)?;
        let bytes = canonical_bytes(&payload)?;
        Ok(SignedConnectorPackage {
            algorithm: SIGNATURE_ALGORITHM.into(),
            publisher_id: self.publisher_id.clone(),
            payload,
            payload_digest_sha256: hex(&Sha256::digest(&bytes)),
            signature_base64: STANDARD_NO_PAD.encode(self.key.sign(&bytes).to_bytes()),
        })
    }
}

pub fn manifest_digest(manifest: &ConnectorManifest) -> Result<String> {
    validate_manifest(manifest)?;
    Ok(hex(&Sha256::digest(canonical_bytes(manifest)?)))
}

pub fn validate_manifest(manifest: &ConnectorManifest) -> Result<()> {
    if manifest.schema_version != CONNECTOR_MANIFEST_VERSION {
        return Err(KeyLeaseError::UnsupportedVersion {
            version: manifest.schema_version,
        });
    }
    validate_identifier(&manifest.provider, "provider")?;
    validate_text(&manifest.display_name, 200, "display name")?;
    validate_version(&manifest.version)?;
    if manifest.authentication_methods.is_empty()
        || manifest.authentication_methods.len() > 16
        || manifest.actions.is_empty()
        || manifest.actions.len() > 256
    {
        return invalid("connector authentication methods/actions must be non-empty and bounded");
    }
    let mut auth_methods = BTreeSet::new();
    for method in &manifest.authentication_methods {
        validate_identifier(method, "authentication method")?;
        if !auth_methods.insert(method) {
            return invalid("duplicate connector authentication method");
        }
    }
    let mut origins = BTreeSet::new();
    for origin in &manifest.fixed_https_origins {
        validate_https_origin(origin)?;
        if !origins.insert(origin) {
            return invalid("duplicate connector HTTPS origin");
        }
    }
    if manifest.runtime == ConnectorRuntime::OutOfProcess && origins.is_empty() {
        return invalid("out-of-process connector requires a fixed outbound origin");
    }
    if let Some(oauth) = &manifest.oauth {
        validate_https_url(
            &oauth.authorization_endpoint,
            "OAuth authorization endpoint",
        )?;
        validate_https_url(&oauth.token_endpoint, "OAuth token endpoint")?;
        if oauth.supported_scopes.len() > 128
            || oauth.supported_scopes.iter().any(|scope| {
                scope.is_empty() || scope.len() > 500 || scope.chars().any(char::is_control)
            })
        {
            return invalid("invalid OAuth supported scope list");
        }
    }

    let mut action_names = BTreeSet::new();
    for action in &manifest.actions {
        validate_action_name(&action.name)?;
        if !action_names.insert(&action.name) {
            return invalid("duplicate connector action name");
        }
        validate_resource_prefix(&action.resource_prefix)?;
        if action.required_fields.len() > action.allowed_fields.len()
            || !action
                .required_fields
                .iter()
                .all(|field| action.allowed_fields.contains_key(field))
        {
            return invalid("required action fields must be a subset of allowed fields");
        }
        if action.allowed_fields.keys().any(|field| {
            field.is_empty()
                || field.len() > 100
                || !field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }) {
            return invalid("action field names must be canonical identifiers");
        }
        if matches!(action.risk, RiskTier::R0 | RiskTier::R1) && !action.idempotent {
            return invalid("R0/R1 connector actions must be idempotent");
        }
        if !matches!(action.content_access, keylease_core::ContentAccess::None)
            && action.default_budget.max_response_bytes.is_none()
        {
            return invalid("data-returning action requires a response-byte budget");
        }
        if action
            .default_budget
            .max_response_bytes
            .is_some_and(|limit| limit == 0 || limit > 64 * 1024 * 1024)
        {
            return invalid("connector response-byte budget is outside hard limits");
        }
    }
    Ok(())
}

pub fn conformance_report(manifest: &ConnectorManifest) -> ConformanceReport {
    let validation = validate_manifest(manifest);
    let digest = validation
        .as_ref()
        .ok()
        .and_then(|_| canonical_bytes(manifest).ok())
        .map(|bytes| hex(&Sha256::digest(bytes)))
        .unwrap_or_default();
    let checks = vec![
        check(
            "manifest_shape",
            validation.is_ok(),
            validation
                .as_ref()
                .err()
                .map_or("versioned manifest accepted".into(), ToString::to_string),
        ),
        check(
            "deny_unknown_fields",
            serde_json::to_value(manifest)
                .ok()
                .and_then(|mut value| {
                    value
                        .as_object_mut()?
                        .insert("unknown_authority".into(), Value::Bool(true));
                    Some(serde_json::from_value::<ConnectorManifest>(value).is_err())
                })
                .unwrap_or(false),
            "unknown manifest authority is rejected".into(),
        ),
        check(
            "typed_actions",
            manifest.actions.iter().all(|action| {
                action
                    .required_fields
                    .iter()
                    .all(|name| action.allowed_fields.contains_key(name))
            }),
            "required fields are declared in the typed schema".into(),
        ),
        check(
            "fixed_egress",
            manifest.runtime == ConnectorRuntime::BuiltIn
                || !manifest.fixed_https_origins.is_empty(),
            "custom runtime has an explicit outbound allowlist".into(),
        ),
    ];
    ConformanceReport {
        provider: manifest.provider.clone(),
        connector_version: manifest.version.clone(),
        manifest_digest_sha256: digest,
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

pub fn verify_signed_package(
    package: &SignedConnectorPackage,
    verifying_key_base64: &str,
) -> Result<String> {
    if package.algorithm != SIGNATURE_ALGORITHM {
        return invalid("unsupported connector package signature algorithm");
    }
    validate_identifier(&package.publisher_id, "publisher id")?;
    validate_package_payload(&package.payload)?;
    let bytes = canonical_bytes(&package.payload)?;
    let digest = hex(&Sha256::digest(&bytes));
    if digest != package.payload_digest_sha256 {
        return Err(KeyLeaseError::Denied {
            reason: "connector package payload digest mismatch".into(),
        });
    }
    let public = decode_verifying_key(verifying_key_base64)?;
    let signature: [u8; 64] = STANDARD_NO_PAD
        .decode(&package.signature_base64)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid connector package signature encoding".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid connector package signature length".into(),
        })?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| KeyLeaseError::Crypto)?
        .verify(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| KeyLeaseError::Denied {
            reason: "connector package signature verification failed".into(),
        })?;
    manifest_digest(&package.payload.manifest)
}

pub fn validate_publisher_verifying_key(verifying_key_base64: &str) -> Result<()> {
    VerifyingKey::from_bytes(&decode_verifying_key(verifying_key_base64)?)
        .map(|_| ())
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid connector publisher Ed25519 key".into(),
        })
}

/// JSON Schema for a provider action nested under LeaseGate's execution
/// envelope. `additionalProperties: false` preserves deny-unknown behavior in
/// MCP clients before the request reaches the enforcement point.
pub fn action_input_schema(
    manifest: &ConnectorManifest,
    action_name: &str,
) -> Result<Map<String, Value>> {
    validate_manifest(manifest)?;
    let action = manifest
        .actions
        .iter()
        .find(|action| action.name == action_name)
        .ok_or_else(|| KeyLeaseError::NotFound {
            resource: action_name.into(),
        })?;
    let argument_properties = action
        .allowed_fields
        .iter()
        .map(|(name, kind)| (name.clone(), json!({"type": json_type_name(kind)})))
        .collect::<Map<_, _>>();
    let properties = json!({
        "connection_id": {"type":"string", "minLength":1, "maxLength":200},
        "resource": {"type":"string", "pattern": format!("^{}(?:[/:].+)?$", regex_literal(&action.resource_prefix))},
        "arguments": {
            "type":"object",
            "properties": argument_properties,
            "required": action.required_fields,
            "additionalProperties": false
        },
        "idempotency_key": {"type":"string", "minLength":1, "maxLength":256},
        "task_id": {"type":["string","null"]},
        "lease_token": {"type":["string","null"]},
        "approval_id": {"type":["string","null"]},
        "lease_ttl_seconds": {"type":"integer", "minimum":1, "maximum":3600},
        "max_uses": {"type":"integer", "minimum":1, "maximum":1000}
    });
    Ok(json!({
        "type":"object",
        "properties": properties,
        "required":["connection_id","resource","arguments","idempotency_key"],
        "additionalProperties":false
    })
    .as_object()
    .expect("static schema object")
    .clone())
}

fn validate_package_payload(payload: &ConnectorPackagePayload) -> Result<()> {
    if payload.schema_version != CONNECTOR_PACKAGE_VERSION {
        return Err(KeyLeaseError::UnsupportedVersion {
            version: payload.schema_version,
        });
    }
    validate_manifest(&payload.manifest)?;
    if !is_sha256(&payload.artifact_digest_sha256)
        || payload.published_at > Utc::now() + chrono::Duration::minutes(5)
    {
        return invalid("invalid connector artifact digest or publication time");
    }
    Ok(())
}

fn decode_verifying_key(encoded: &str) -> Result<[u8; 32]> {
    STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid connector publisher key encoding".into(),
        })?
        .try_into()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "invalid connector publisher key length".into(),
        })
}

fn regex_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
    {
        return invalid(&format!("invalid {label}"));
    }
    Ok(())
}

fn validate_action_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 200
        || value.split('.').count() < 2
        || !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.'))
    {
        return invalid("invalid canonical connector action name");
    }
    Ok(())
}

fn validate_resource_prefix(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 300
        || !value.contains(':')
        || value.contains("//")
        || value.ends_with('/')
        || value.split('/').any(|part| part == "." || part == "..")
        || value
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '_' | '-' | '.')))
    {
        return invalid("invalid canonical resource prefix");
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
    {
        return invalid("invalid connector version");
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return invalid(&format!("invalid connector {label}"));
    }
    Ok(())
}

fn validate_https_origin(value: &str) -> Result<()> {
    let url = validate_https_url(value, "outbound origin")?;
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return invalid(
            "connector outbound origin must not contain path, credentials, query or fragment",
        );
    }
    Ok(())
}

fn validate_https_url(value: &str, label: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: format!("invalid {label}"),
    })?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return invalid(&format!("{label} must use HTTPS with an explicit host"));
    }
    Ok(url)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "connector artifact cannot be canonicalized as RFC 8785 JSON".into(),
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn json_type_name(kind: &JsonType) -> &'static str {
    match kind {
        JsonType::String => "string",
        JsonType::Number => "number",
        JsonType::Boolean => "boolean",
        JsonType::Array => "array",
        JsonType::Object => "object",
    }
}

fn check(name: &str, passed: bool, detail: String) -> ConformanceCheck {
    ConformanceCheck {
        name: name.into(),
        passed,
        detail,
    }
}

fn invalid<T>(reason: &str) -> Result<T> {
    Err(KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use leasegate_connectors::{
        Connector, FakeConnector, jira_manifest, notion_manifest, slack_manifest,
    };

    #[test]
    fn reference_connectors_pass_manifest_conformance() {
        for manifest in [
            FakeConnector::default().manifest(),
            notion_manifest(),
            slack_manifest(),
            jira_manifest(),
        ] {
            let report = conformance_report(&manifest);
            assert!(report.passed, "{report:#?}");
            assert_eq!(report.manifest_digest_sha256.len(), 64);
        }
    }

    #[test]
    fn signed_package_rejects_manifest_or_artifact_tampering() {
        let signer = ConnectorPackageSigner::generate("publisher_test").unwrap();
        validate_publisher_verifying_key(&signer.verifying_key_base64()).unwrap();
        assert!(validate_publisher_verifying_key("not-a-key").is_err());
        let mut package = signer
            .sign(ConnectorPackagePayload {
                schema_version: CONNECTOR_PACKAGE_VERSION,
                manifest: notion_manifest(),
                artifact_digest_sha256: "a".repeat(64),
                published_at: Utc::now(),
            })
            .unwrap();
        verify_signed_package(&package, &signer.verifying_key_base64()).unwrap();
        package.payload.manifest.actions[0].name = "notion.page.escalate".into();
        assert!(verify_signed_package(&package, &signer.verifying_key_base64()).is_err());
    }

    #[test]
    fn generated_action_schema_denies_unknown_arguments() {
        let mut manifest = notion_manifest();
        manifest.actions[0].resource_prefix = "notion:page.v1".into();
        let action = manifest.actions[0].name.clone();
        let schema = action_input_schema(&manifest, &action).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["arguments"]["additionalProperties"],
            false
        );
        assert!(
            schema["properties"]["resource"]["pattern"]
                .as_str()
                .unwrap()
                .contains("page\\.v1")
        );
    }
}
