//! Database access without disclosing the password (ADR 0005, tier T1).
//!
//! `keylease db` runs a local PostgreSQL proxy in the agent's process. The
//! proxy speaks to the real server, but when the server asks for SCRAM-SHA-256
//! authentication it hands the exchange to the service, which computes the
//! client proof from the stored password and returns only the proof. The
//! password never leaves this boundary, and every connection is a policy
//! decision on `db:connect` for that item, database and role.

use super::*;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// SCRAM iteration counts outside this range are refused: too few is weak,
/// too many lets a hostile server make the service burn CPU.
const SCRAM_ITERATIONS: std::ops::RangeInclusive<u32> = 4096..=1_000_000;

/// Where and as whom a database item connects. Contains no secret.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DbTarget {
    pub item_id: ItemId,
    pub title: String,
    pub engine: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub environment: Option<String>,
}

/// The SCRAM client-final message and the server signature to expect.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScramClientFinal {
    pub client_final: String,
    pub server_signature: String,
}

fn text_field(item: &VaultItem, key: &str) -> Option<String> {
    item.fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field_value_string(&field.value))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn db_target(item: &VaultItem) -> Result<DbTarget> {
    let invalid = |reason: &str| KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    };
    if item.kind != "core.database" {
        return Err(invalid("item is not a Database item"));
    }
    let engine = text_field(item, "engine").unwrap_or_else(|| "postgresql".into());
    if !matches!(
        engine.to_ascii_lowercase().as_str(),
        "postgres" | "postgresql" | "pg"
    ) {
        return Err(invalid("only PostgreSQL database items are supported"));
    }
    let host = text_field(item, "host").ok_or_else(|| invalid("database item has no host"))?;
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/')
    {
        return Err(invalid("database host must be a hostname or IP address"));
    }
    let port = match text_field(item, "port") {
        Some(value) => value
            .parse::<f64>()
            .ok()
            .filter(|port| port.fract() == 0.0 && (1.0..=65535.0).contains(port))
            .map(|port| port as u16)
            .ok_or_else(|| invalid("database port is invalid"))?,
        None => 5432,
    };
    Ok(DbTarget {
        item_id: item.id.clone(),
        title: item.title.clone(),
        engine: "postgresql".into(),
        host,
        port,
        database: text_field(item, "database").unwrap_or_else(|| "postgres".into()),
        username: text_field(item, "username")
            .ok_or_else(|| invalid("database item has no username"))?,
        environment: item.environment.clone(),
    })
}

/// Production items get the stricter tier, which caps trust at one hour.
fn connect_risk(item: &VaultItem) -> RiskTier {
    match item.environment.as_deref().map(str::to_ascii_lowercase) {
        Some(environment) if environment.starts_with("prod") => RiskTier::R3,
        _ => RiskTier::R2,
    }
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Splits `a=…,b=…` SCRAM attributes.
fn scram_attributes(message: &str) -> BTreeMap<char, &str> {
    message
        .split(',')
        .filter_map(|part| {
            let mut characters = part.chars();
            let key = characters.next()?;
            (characters.next() == Some('=')).then(|| (key, &part[2..]))
        })
        .collect()
}

/// Computes the SCRAM-SHA-256 client-final message (RFC 5802, RFC 7677)
/// without channel binding, as PostgreSQL accepts with `n,,`.
pub(crate) fn scram_client_final(
    password: &str,
    client_first_bare: &str,
    server_first: &str,
) -> Result<ScramClientFinal> {
    let invalid = |reason: &str| KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    };
    let client = scram_attributes(client_first_bare);
    let server = scram_attributes(server_first);
    let client_nonce = client
        .get(&'r')
        .filter(|nonce| nonce.len() >= 16)
        .ok_or_else(|| invalid("client-first message has no nonce"))?;
    let nonce = server
        .get(&'r')
        .filter(|nonce| nonce.starts_with(client_nonce) && nonce.len() > client_nonce.len())
        .ok_or_else(|| invalid("server nonce does not extend the client nonce"))?;
    let salt = server
        .get(&'s')
        .and_then(|salt| base64::engine::general_purpose::STANDARD.decode(salt).ok())
        .filter(|salt| !salt.is_empty())
        .ok_or_else(|| invalid("server-first message has no salt"))?;
    let iterations = server
        .get(&'i')
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| SCRAM_ITERATIONS.contains(value))
        .ok_or_else(|| invalid("SCRAM iteration count is out of range"))?;

    let mut salted = Zeroizing::new([0_u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, salted.as_mut());
    let client_key = Zeroizing::new(hmac(salted.as_ref(), b"Client Key"));
    let stored_key = Sha256::digest(client_key.as_ref());
    let without_proof = format!("c=biws,r={nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let signature = hmac(&stored_key, auth_message.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(signature.iter())
        .map(|(key, signature)| key ^ signature)
        .collect();
    let server_key = hmac(salted.as_ref(), b"Server Key");
    let server_signature = hmac(&server_key, auth_message.as_bytes());
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    Ok(ScramClientFinal {
        client_final: format!("{without_proof},p={}", encode(&proof)),
        server_signature: encode(&server_signature),
    })
}

impl KeyLeaseService {
    /// Describes where a database item connects, without its password.
    pub fn db_target_authorized(&self, actor: &ActorContext, id: &ItemId) -> Result<DbTarget> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                actor,
                "entry:read_fields",
                &resource,
                Value::Object(Default::default()),
            )?;
            let target = db_target(&self.store.get_item(vault, id)?)?;
            self.audit_vault(
                actor,
                "entry:read_fields",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(target)
        })
    }

    /// Answers a server's SCRAM challenge for a database item.
    ///
    /// Authorization binds the item, database and role, not the nonces, so a
    /// retried connection finds the same approval.
    pub fn db_scram_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        database: &str,
        client_first_bare: &str,
        server_first: &str,
    ) -> Result<ScramClientFinal> {
        if database.is_empty()
            || database.len() > 63
            || database.chars().any(char::is_control)
            || client_first_bare.len() > 1024
            || server_first.len() > 1024
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid SCRAM exchange".into(),
            });
        }
        self.with_vault(|vault| {
            let item = self.store.get_item(vault, id)?;
            let target = db_target(&item)?;
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault_at_risk(
                actor,
                "db:connect",
                &resource,
                serde_json::json!({"database": database, "role": target.username}),
                connect_risk(&item),
            )?;
            let password = Zeroizing::new(text_field(&item, "password").ok_or_else(|| {
                KeyLeaseError::InvalidRequest {
                    reason: "database item has no password".into(),
                }
            })?);
            let answer = scram_client_final(&password, client_first_bare, server_first)?;
            self.audit_vault(actor, "db:connect", &resource, "allow", "success", vec![])?;
            Ok(answer)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 section 3 test vector.
    #[test]
    fn scram_matches_the_rfc_7677_vector() {
        let answer = scram_client_final(
            "pencil",
            "n=user,r=rOprNGfwEbeRWgbNEkqO",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        )
        .unwrap();
        assert_eq!(
            answer.client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(
            answer.server_signature,
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
    }

    #[test]
    fn hostile_server_parameters_are_refused() {
        let client = "n=,r=abcdefghijklmnopqrstuvwx";
        for server in [
            "r=zzzz,s=c2FsdA==,i=4096",
            "r=abcdefghijklmnopqrstuvwxSERVER,s=,i=4096",
            "r=abcdefghijklmnopqrstuvwxSERVER,s=c2FsdA==,i=1",
            "r=abcdefghijklmnopqrstuvwxSERVER,s=c2FsdA==,i=999999999",
        ] {
            assert!(
                scram_client_final("pw", client, server).is_err(),
                "{server}"
            );
        }
    }

    #[test]
    fn production_items_are_a_higher_tier() {
        let mut item: VaultItem = serde_json::from_value(serde_json::json!({
            "id": "item_x", "vault_id": "vault_x", "group_id": "group_x",
            "kind": "core.database", "title": "db", "sections": [], "fields": [],
            "urls": [], "tags": [], "attachments": [], "notes": null,
            "schema_version": 1, "revision": 1,
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "secret_changed_at": null, "expires_at": null,
            "rotation_interval_days": null, "issuer": null, "environment": null,
            "status": "active"
        }))
        .unwrap();
        assert_eq!(connect_risk(&item), RiskTier::R2);
        item.environment = Some("Production".into());
        assert_eq!(connect_risk(&item), RiskTier::R3);
    }
}
