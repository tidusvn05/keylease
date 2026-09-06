use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use keylease_core::{KeyLeaseError, Result};
use leasegate_control::OidcProvider;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VerifiedOidcIdentity {
    pub subject: String,
    pub email: Option<String>,
    #[allow(dead_code)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

pub(crate) async fn verify_id_token(
    provider: &OidcProvider,
    token: &str,
    _now: DateTime<Utc>,
) -> Result<VerifiedOidcIdentity> {
    provider.validate()?;
    if !provider.enabled || token.is_empty() || token.len() > 64 * 1024 {
        return Err(denied("OIDC provider is disabled or token is invalid"));
    }
    let header = decode_header(token).map_err(|_| denied("invalid OIDC token header"))?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    ) {
        return Err(denied(
            "OIDC token must use an asymmetric signing algorithm",
        ));
    }
    let kid = header
        .kid
        .ok_or_else(|| denied("OIDC token has no key identifier"))?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .map_err(|_| KeyLeaseError::Storage)?;
    let mut response = http
        .get(&provider.jwks_uri)
        .send()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    if !response.status().is_success() {
        return Err(KeyLeaseError::ConnectorUnavailable {
            retryable: response.status().is_server_error(),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > 1024 * 1024)
    {
        return Err(denied("OIDC JWKS exceeds size limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?
    {
        if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
            return Err(denied("OIDC JWKS exceeds size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let set: JwkSet = serde_json::from_slice(&bytes).map_err(|_| denied("invalid OIDC JWKS"))?;
    let jwk = set
        .find(&kid)
        .ok_or_else(|| denied("OIDC signing key is unknown"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| denied("unsupported OIDC signing key"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 30;
    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(|_| denied("OIDC signature or claims validation failed"))?
        .claims;
    if claims.subject_invalid() {
        return Err(denied("OIDC subject is invalid"));
    }
    if !provider.allowed_email_domains.is_empty() {
        let domain = claims
            .email
            .as_deref()
            .and_then(|email| email.rsplit_once('@'))
            .map(|(_, domain)| domain);
        if domain.is_none_or(|domain| {
            !provider
                .allowed_email_domains
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(domain))
        }) {
            return Err(denied("OIDC email domain is not allowed"));
        }
    }
    Ok(VerifiedOidcIdentity {
        subject: claims.sub,
        email: claims.email,
        groups: claims.groups,
    })
}

impl Claims {
    fn subject_invalid(&self) -> bool {
        self.sub.is_empty() || self.sub.len() > 1024 || self.sub.chars().any(char::is_control)
    }
}

fn denied(reason: &str) -> KeyLeaseError {
    KeyLeaseError::Denied {
        reason: reason.into(),
    }
}
