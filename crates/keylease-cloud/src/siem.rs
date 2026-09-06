use crate::AuditExportBatch;
use chrono::Utc;
use hmac::{Hmac, Mac};
use keylease_core::{KeyLeaseError, Result};
use leasegate_control::{SiemDestination, SiemFormat};
use serde::Deserialize;
use sha2::Sha256;
use std::{collections::BTreeMap, fs, path::Path, time::Duration};
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretReferences {
    secrets: BTreeMap<String, String>,
}

pub struct SiemExporter {
    secret_paths: BTreeMap<String, String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for SiemExporter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiemExporter")
            .field("secret_refs", &self.secret_paths.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SiemExporter {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = read_secret_file(path, 256 * 1024)?;
        let config: SecretReferences =
            serde_json::from_str(&raw).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid SIEM secret-reference file".into(),
            })?;
        if config.secrets.len() > 100
            || config.secrets.iter().any(|(name, path)| {
                name.is_empty() || name.len() > 128 || path.is_empty() || path.len() > 4096
            })
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid SIEM secret references".into(),
            });
        }
        for secret_path in config.secrets.values() {
            validate_secret_file(Path::new(secret_path), 64 * 1024)?;
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(Self {
            secret_paths: config.secrets,
            http,
        })
    }

    pub async fn export(
        &self,
        destination: &SiemDestination,
        batch: &AuditExportBatch,
    ) -> Result<()> {
        if batch.events.is_empty() {
            return Ok(());
        }
        let endpoint =
            Url::parse(&destination.endpoint).map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid SIEM endpoint".into(),
            })?;
        if endpoint.scheme() != "https" {
            return Err(KeyLeaseError::Denied {
                reason: "SIEM endpoint must use HTTPS".into(),
            });
        }
        let secret_path = self
            .secret_paths
            .get(&destination.secret_ref)
            .ok_or_else(|| KeyLeaseError::Denied {
                reason: "SIEM secret reference is not configured locally".into(),
            })?;
        let secret = read_secret_file(Path::new(secret_path), 64 * 1024)?;
        let payload = encode_payload(destination, batch)?;
        let timestamp = Utc::now().timestamp().to_string();
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| KeyLeaseError::Crypto)?;
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(&payload);
        let signature = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let response = self
            .http
            .post(endpoint)
            .header("content-type", "application/json")
            .header("x-leasegate-timestamp", timestamp)
            .header("x-leasegate-signature-sha256", signature)
            .body(payload)
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        if !response.status().is_success() {
            return Err(KeyLeaseError::ConnectorUnavailable {
                retryable: response.status().is_server_error(),
            });
        }
        Ok(())
    }
}

fn encode_payload(destination: &SiemDestination, batch: &AuditExportBatch) -> Result<Vec<u8>> {
    let records = match destination.format {
        SiemFormat::Json => serde_json::to_value(&batch.events).map_err(|_| KeyLeaseError::Storage)?,
        SiemFormat::Cef => serde_json::Value::Array(batch.events.iter().map(|event| {
            serde_json::Value::String(format!(
                "CEF:0|LeaseGate|Control|1|{}|{}|5|requestId={} agentId={} resource={} decision={} outcome={}",
                cef(&event.action), cef(&event.action), cef(&event.request_id.0),
                cef(&event.agent_id.0), cef(&event.resource), cef(&event.decision), cef(&event.outcome)
            ))
        }).collect()),
    };
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "schema_version": 1,
        "destination_id": destination.destination_id,
        "after": batch.after,
        "cursor": batch.cursor,
        "records": records,
    }))
    .map_err(|_| KeyLeaseError::Storage)
}

fn cef(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

fn validate_secret_file(path: &Path, maximum: u64) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|_| KeyLeaseError::Storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyLeaseError::Denied {
                reason: "SIEM secret file must be mode 0600".into(),
            });
        }
    }
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "invalid SIEM secret file".into(),
        });
    }
    Ok(())
}

fn read_secret_file(path: &Path, maximum: u64) -> Result<Zeroizing<String>> {
    validate_secret_file(path, maximum)?;
    Ok(Zeroizing::new(
        fs::read_to_string(path).map_err(|_| KeyLeaseError::Storage)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use keylease_core::{AgentId, RequestId, SiemDestinationId};
    use leasegate_control::{SiemDestination, SiemFormat};

    #[test]
    fn cef_payload_escapes_delimiters_and_contains_no_argument_values() {
        let destination = SiemDestination {
            schema_version: 1,
            destination_id: SiemDestinationId::new(),
            organization_id: keylease_core::OrganizationId::new(),
            project_id: keylease_core::ProjectId::new(),
            display_name: "SIEM".into(),
            format: SiemFormat::Cef,
            endpoint: "https://siem.example.test/events".into(),
            secret_ref: "primary".into(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let event = keylease_core::AuditEvent {
            schema_version: 1,
            timestamp: Utc::now(),
            request_id: RequestId::new(),
            agent_id: AgentId::new(),
            workload_id: None,
            on_behalf_of: None,
            action: "test|action".into(),
            resource: "test:item=1".into(),
            connection_id: None,
            policy_version: None,
            decision: "allow".into(),
            connector: None,
            outcome: "success".into(),
            item_count: None,
            cell_count: None,
            byte_count: None,
            changed_fields: vec![],
        };
        let batch = AuditExportBatch {
            destination_id: destination.destination_id.clone(),
            after: 0,
            cursor: 1,
            events: vec![event],
        };
        let payload = String::from_utf8(encode_payload(&destination, &batch).unwrap()).unwrap();
        assert!(payload.contains("test\\\\|action"));
        assert!(!payload.contains("arguments"));
    }
}
