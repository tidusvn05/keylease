//! The HTTP credential broker (ADR 0007, tier T1): an agent calls an HTTP API
//! through KeyLease, which adds the credential and forwards the request. The
//! secret never leaves this process: the agent's side only ever sees the
//! response, scrubbed of the secret.
//!
//! An item opts in with an **HTTP binding**: the upstream base URL and the
//! header to add (`Authorization: Bearer {secret}` by default). Requests may
//! only go below that base URL, to public addresses (unless the binding allows
//! private ones), without following redirects.

use super::*;

/// Item extension holding the binding.
pub const HTTP_EXTENSION: &str = "keylease.http";
/// Request and response bodies are buffered up to this size (the local RPC
/// carries them base64-encoded in one JSON line).
pub const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_HTTP_HEADERS: usize = 100;
const HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(120);
const REDACTED: &[u8] = b"[REDACTED by keylease]";

/// Where an item's secret may be sent, and how.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpBinding {
    /// Requests go below this URL (`https://api.example.com/v1`). https only;
    /// http is accepted for loopback hosts.
    pub base_url: String,
    /// The header that carries the credential.
    #[serde(default = "default_header")]
    pub header: String,
    /// Its value: `{secret}` is the field's value, `{basic}` is
    /// base64(username:secret) for Basic authentication.
    #[serde(default = "default_template")]
    pub template: String,
    /// The field holding the secret (default: `credential`, else `password`).
    #[serde(default)]
    pub field: Option<String>,
    /// Allow private, loopback and link-local addresses (a local service).
    #[serde(default)]
    pub allow_private: bool,
}

fn default_header() -> String {
    "Authorization".into()
}

fn default_template() -> String {
    "Bearer {secret}".into()
}

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpForwardRequest {
    /// The bound item (an ID, or a named reference `ref:PROJECT/ENV/ITEM`).
    pub item_id: ItemId,
    pub method: String,
    /// Path and query below the binding's base URL, starting with `/`.
    pub path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_b64: Option<String>,
}

impl std::fmt::Debug for HttpForwardRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpForwardRequest")
            .field("item_id", &self.item_id)
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpForwardResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_b64: String,
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

fn invalid(reason: impl Into<String>) -> KeyLeaseError {
    KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

impl HttpBinding {
    pub fn validate(&self) -> Result<reqwest::Url> {
        let url = reqwest::Url::parse(&self.base_url)
            .map_err(|_| invalid("base URL must be an absolute URL"))?;
        let host = url
            .host_str()
            .ok_or_else(|| invalid("base URL needs a host"))?;
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err(invalid("base URL must use https (http only for localhost)")),
        }
        if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
            return Err(invalid(
                "base URL must not have a query, fragment or user info",
            ));
        }
        if !valid_header_name(&self.header) {
            return Err(invalid("invalid header name"));
        }
        if !(self.template.contains("{secret}") || self.template.contains("{basic}"))
            || self.template.len() > 256
            || self.template.chars().any(char::is_control)
        {
            return Err(invalid(
                "the header template must contain {secret} or {basic} and no control characters",
            ));
        }
        Ok(url)
    }
}

/// Whether `address` is safe to reach without `allow_private`.
fn public_address(address: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_address(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// The target URL for `path` below `base`, refusing anything that would
/// leave it (`..`, an absolute URL, a different origin).
fn target_url(base: &reqwest::Url, path: &str) -> Result<reqwest::Url> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') || path.len() > 8192
    {
        return Err(invalid(
            "path must start with a single / and be at most 8 KiB",
        ));
    }
    let (path_part, query) = match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    };
    if path_part.split('/').any(|segment| {
        matches!(segment, "." | "..")
            || segment.eq_ignore_ascii_case("%2e%2e")
            || segment.eq_ignore_ascii_case("%2e")
    }) {
        return Err(invalid("path must not contain . or .. segments"));
    }
    let mut url = base.clone();
    let joined = format!("{}{}", base.path().trim_end_matches('/'), path_part);
    url.set_path(&joined);
    url.set_query(query);
    if url.origin() != base.origin() || !url.path().starts_with(base.path().trim_end_matches('/')) {
        return Err(invalid("path leaves the binding's base URL"));
    }
    Ok(url)
}

fn scrub(body: &[u8], secrets: &[Zeroizing<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0;
    'outer: while index < body.len() {
        for secret in secrets {
            if !secret.is_empty() && body[index..].starts_with(secret) {
                out.extend_from_slice(REDACTED);
                index += secret.len();
                continue 'outer;
            }
        }
        out.push(body[index]);
        index += 1;
    }
    out
}

fn secret_forms(secret: &str) -> Vec<Zeroizing<Vec<u8>>> {
    use base64::engine::general_purpose::STANDARD;
    if secret.len() < 4 {
        return vec![];
    }
    let mut forms = vec![
        Zeroizing::new(secret.as_bytes().to_vec()),
        Zeroizing::new(STANDARD.encode(secret.as_bytes()).into_bytes()),
    ];
    forms.sort_by_key(|form| std::cmp::Reverse(form.len()));
    forms
}

/// What the vault part of a forward decided.
struct Prepared {
    url: reqwest::Url,
    header: String,
    value: Zeroizing<String>,
    scrub: Vec<Zeroizing<Vec<u8>>>,
    allow_private: bool,
    resource: String,
}

impl KeyLeaseService {
    /// Sets or removes an item's HTTP binding.
    ///
    /// Changing where a secret may be sent is a protected change
    /// (`entry:update_protected_fields`, R3): a binding to another host would
    /// hand it over.
    pub fn set_http_binding_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        binding: Option<HttpBinding>,
    ) -> Result<Option<HttpBinding>> {
        if let Some(binding) = &binding {
            binding.validate()?;
        }
        self.with_vault(|vault| {
            let mut item = self.store.get_item(vault, id)?;
            refuse_shared_copy(&item)?;
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                "entry:update_protected_fields",
                &resource,
                serde_json::json!({"operation":"http_binding","binding":binding}),
            )?;
            match &binding {
                Some(binding) => {
                    item.extensions.insert(
                        HTTP_EXTENSION.into(),
                        serde_json::to_value(binding).map_err(|_| KeyLeaseError::Storage)?,
                    );
                }
                None => {
                    item.extensions.remove(HTTP_EXTENSION);
                }
            }
            let expected = item.revision;
            item.revision += 1;
            item.updated_at = Utc::now();
            let idempotency_key = random_token("http-binding");
            let request_material = operation_material(&serde_json::json!({
                "operation":"http_binding","item":id,"binding":binding,"revision":item.revision,
            }))?;
            let audit = self.vault_audit_event(
                actor,
                "entry:update_protected_fields",
                &id.0,
                "allow",
                "success",
                vec!["http_binding".into()],
            );
            self.store.put_item(
                vault,
                &item,
                Some(expected),
                MutationContext {
                    actor: &actor.agent_id.0,
                    idempotency_key: &idempotency_key,
                    request_material: &request_material,
                    audit_event: Some(&audit),
                },
            )?;
            Ok(binding)
        })
    }

    /// An item's HTTP binding (metadata read).
    pub fn http_binding_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
    ) -> Result<Option<HttpBinding>> {
        self.with_vault(|vault| {
            let id = self.resolve_item_reference(vault, actor, id)?;
            let item = self.store.get_item(vault, &id)?;
            self.authorize_vault(
                vault,
                actor,
                "entry:read_metadata",
                &format!("kl://{}/{}", vault.vault_id.0, id.0),
                Value::Object(Default::default()),
            )?;
            item_http_binding(&item)
        })
    }

    pub(crate) fn resolve_item_reference(
        &self,
        vault: &UnlockedVault,
        actor: &ActorContext,
        id: &ItemId,
    ) -> Result<ItemId> {
        match id.0.strip_prefix("ref:") {
            Some(path) => self.resolve_named_item(vault, actor, path),
            None => Ok(id.clone()),
        }
    }

    /// Forwards one request to the item's bound API with its credential.
    ///
    /// Policy action `http:request` on the item, arguments `{host, method}`:
    /// R1 for GET, HEAD and OPTIONS, R2 otherwise, R3 in a protected
    /// environment. The response body is scrubbed of the secret.
    pub async fn http_forward_authorized(
        &self,
        actor: &ActorContext,
        request: HttpForwardRequest,
    ) -> Result<HttpForwardResponse> {
        let method =
            reqwest::Method::from_bytes(request.method.trim().to_ascii_uppercase().as_bytes())
                .map_err(|_| invalid("invalid HTTP method"))?;
        if method == reqwest::Method::CONNECT || method == reqwest::Method::TRACE {
            return Err(invalid("CONNECT and TRACE are not forwarded"));
        }
        if request.headers.len() > MAX_HTTP_HEADERS {
            return Err(invalid("too many headers"));
        }
        let body = match &request.body_b64 {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| invalid("body must be base64"))?,
            None => Vec::new(),
        };
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Err(invalid(format!(
                "request body is limited to {MAX_HTTP_BODY_BYTES} bytes"
            )));
        }
        let prepared = self.with_vault(|vault| {
            let id = self.resolve_item_reference(vault, actor, &request.item_id)?;
            let item = self.store.get_item(vault, &id)?;
            let binding = item_http_binding(&item)?.ok_or_else(|| {
                invalid(format!(
                    "{} has no HTTP binding; set one with `keylease http bind`",
                    item.title
                ))
            })?;
            let base = binding.validate()?;
            let url = target_url(&base, &request.path)?;
            let host = url.host_str().unwrap_or_default().to_owned();
            let safe_method = matches!(
                method,
                reqwest::Method::GET | reqwest::Method::HEAD | reqwest::Method::OPTIONS
            );
            let risk = if self.item_environment_protected(vault, &item)? {
                RiskTier::R3
            } else if safe_method {
                RiskTier::R1
            } else {
                RiskTier::R2
            };
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault_at_risk(
                vault,
                actor,
                "http:request",
                &resource,
                serde_json::json!({"host": host, "method": method.as_str()}),
                risk,
            )?;
            let field_key = binding.field.clone().unwrap_or_else(|| {
                if item.fields.iter().any(|field| field.key == "credential") {
                    "credential".into()
                } else {
                    "password".into()
                }
            });
            let secret = item
                .fields
                .iter()
                .find(|field| field.key == field_key)
                .map(|field| Zeroizing::new(field_value_string(&field.value)))
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| {
                    invalid(format!("{} has no value in field {field_key}", item.title))
                })?;
            let mut value = Zeroizing::new(binding.template.replace("{secret}", &secret));
            if value.contains("{basic}") {
                let username = item
                    .fields
                    .iter()
                    .find(|field| field.key == "username")
                    .map(|field| field_value_string(&field.value))
                    .unwrap_or_default();
                let pair = Zeroizing::new(format!("{username}:{}", secret.as_str()));
                let encoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()),
                );
                value = Zeroizing::new(value.replace("{basic}", &encoded));
            }
            if value
                .chars()
                .any(|character| character == '\r' || character == '\n')
            {
                return Err(invalid("the secret cannot be sent in a header"));
            }
            let mut scrub = secret_forms(&secret);
            scrub.extend(secret_forms(&value));
            scrub.sort_by_key(|form| std::cmp::Reverse(form.len()));
            Ok(Prepared {
                url,
                header: binding.header.clone(),
                value,
                scrub,
                allow_private: binding.allow_private,
                resource,
            })
        })?;

        let host = prepared.url.host_str().unwrap_or_default().to_owned();
        let port = prepared.url.port_or_known_default().unwrap_or(443);
        let lookup_host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let addresses: Vec<std::net::SocketAddr> =
            tokio::net::lookup_host((lookup_host.as_str(), port))
                .await
                .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?
                .collect();
        let Some(address) = addresses.first().copied() else {
            return Err(KeyLeaseError::ConnectorUnavailable { retryable: true });
        };
        if !prepared.allow_private
            && addresses
                .iter()
                .any(|address| !public_address(address.ip()))
        {
            self.audit_vault(
                actor,
                "http:request",
                &prepared.resource,
                "deny",
                "private_address",
                vec![],
            )?;
            return Err(KeyLeaseError::Denied {
                reason: format!(
                    "{host} resolves to a private address; the binding must allow private addresses"
                ),
            });
        }
        // Connect to the address that was checked, so a second lookup cannot
        // rebind the name to an internal host.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .resolve(&lookup_host, address)
            .build()
            .map_err(|_| KeyLeaseError::Storage)?;
        let mut builder = client.request(method.clone(), prepared.url.clone());
        for (name, value) in &request.headers {
            let lower = name.to_ascii_lowercase();
            if !valid_header_name(name)
                || HOP_BY_HOP.contains(&lower.as_str())
                || lower == prepared.header.to_ascii_lowercase()
                || lower == "accept-encoding"
                || value
                    .chars()
                    .any(|character| character == '\r' || character == '\n')
            {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        // Identity encoding keeps the body readable for scrubbing.
        builder = builder
            .header("accept-encoding", "identity")
            .header(prepared.header.as_str(), prepared.value.as_str());
        if !body.is_empty() {
            builder = builder.body(body);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| !HOP_BY_HOP.contains(&name.as_str()))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let mut received = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?
        {
            if received.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
                self.audit_vault(
                    actor,
                    "http:request",
                    &prepared.resource,
                    "allow",
                    "response_too_large",
                    vec![],
                )?;
                return Err(invalid(format!(
                    "response body is larger than {MAX_HTTP_BODY_BYTES} bytes"
                )));
            }
            received.extend_from_slice(&chunk);
        }
        let headers = headers
            .into_iter()
            .map(|(name, value)| {
                let scrubbed = scrub(value.as_bytes(), &prepared.scrub);
                (name, String::from_utf8_lossy(&scrubbed).into_owned())
            })
            .collect();
        let body = scrub(&received, &prepared.scrub);
        self.audit_vault(
            actor,
            "http:request",
            &prepared.resource,
            "allow",
            &format!("status_{status}"),
            vec![],
        )?;
        Ok(HttpForwardResponse {
            status,
            headers,
            body_b64: base64::engine::general_purpose::STANDARD.encode(body),
        })
    }
}

pub(crate) fn item_http_binding(item: &VaultItem) -> Result<Option<HttpBinding>> {
    item.extensions
        .get(HTTP_EXTENSION)
        .map(|value| serde_json::from_value(value.clone()).map_err(|_| KeyLeaseError::Storage))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_urls_stay_below_the_base() {
        let base = reqwest::Url::parse("https://api.example.com/v1").unwrap();
        assert_eq!(
            target_url(&base, "/charges?limit=3").unwrap().as_str(),
            "https://api.example.com/v1/charges?limit=3"
        );
        for bad in [
            "charges",
            "//evil.example/x",
            "/../admin",
            "/a/%2e%2e/b",
            "/a\\b",
        ] {
            assert!(target_url(&base, bad).is_err(), "{bad}");
        }
        let root = reqwest::Url::parse("https://api.example.com/").unwrap();
        assert_eq!(
            target_url(&root, "/x").unwrap().as_str(),
            "https://api.example.com/x"
        );
    }

    #[test]
    fn private_addresses_are_recognised() {
        for private in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "0.0.0.0",
        ] {
            assert!(!public_address(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
            assert!(public_address(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn bindings_are_validated() {
        let binding = |base: &str, template: &str| HttpBinding {
            base_url: base.into(),
            header: "Authorization".into(),
            template: template.into(),
            field: None,
            allow_private: false,
        };
        assert!(
            binding("https://api.example.com", "Bearer {secret}")
                .validate()
                .is_ok()
        );
        assert!(
            binding("http://localhost:8080", "Basic {basic}")
                .validate()
                .is_ok()
        );
        assert!(
            binding("http://api.example.com", "Bearer {secret}")
                .validate()
                .is_err()
        );
        assert!(
            binding("https://api.example.com?x=1", "Bearer {secret}")
                .validate()
                .is_err()
        );
        assert!(
            binding("https://api.example.com", "Bearer token")
                .validate()
                .is_err()
        );
        assert!(
            binding("https://u:p@api.example.com", "{secret}")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn scrubbing_replaces_raw_and_base64_forms() {
        let forms = secret_forms("sk_live_123");
        let out = scrub(
            b"{\"echo\":\"sk_live_123\",\"b\":\"c2tfbGl2ZV8xMjM=\"}",
            &forms,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("sk_live_123") && !text.contains("c2tfbGl2ZV8xMjM="),
            "{text}"
        );
    }
}
