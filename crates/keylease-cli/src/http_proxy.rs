//! The local side of the HTTP credential broker (ADR 0007): a loopback
//! listener that a tool uses as its API base URL. Each request is sent to the
//! daemon (`http_forward`), which adds the credential and forwards it; this
//! process never holds the secret.
//!
//! URLs carry a random capability (`http://127.0.0.1:PORT/kl-…/`), so other
//! local processes cannot use the listener without it.

use super::*;
use crate::backend::Backend;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use keylease_service::{HttpBinding, HttpForwardRequest, HttpForwardResponse, MAX_HTTP_BODY_BYTES};
use std::collections::BTreeMap;

#[derive(Subcommand)]
pub(crate) enum HttpCommand {
    /// Let an item's secret be used for one HTTP API: requests below
    /// BASE_URL get the header `--header: --template` (a protected change).
    Bind {
        /// Item ID or named reference (kl://PROJECT/ENV/ITEM).
        item: String,
        /// The API's base URL, e.g. https://api.stripe.com.
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value = "Authorization")]
        header: String,
        /// `{secret}` is the field's value; `{basic}` is base64(username:secret).
        #[arg(long, default_value = "Bearer {secret}")]
        template: String,
        /// Field holding the secret (default: credential, else password).
        #[arg(long)]
        field: Option<String>,
        /// Allow private and loopback addresses (a service on your network).
        #[arg(long)]
        allow_private: bool,
    },
    /// Remove an item's HTTP binding.
    Unbind { item: String },
    /// Show an item's HTTP binding.
    Show { item: String },
    /// Serve a local base URL for an item until stopped, for tools configured
    /// once (for example `ANTHROPIC_BASE_URL`).
    Proxy {
        item: String,
        /// Loopback address to listen on (default: a free port).
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: std::net::SocketAddr,
    },
}

fn item_id(reference: &str) -> ItemId {
    let path = reference.strip_prefix("kl://").unwrap_or(reference);
    if path.starts_with("item_") {
        ItemId(path.to_owned())
    } else {
        ItemId(format!("ref:{path}"))
    }
}

pub(crate) async fn http_command(cli: &Cli, daemon: &Path, command: HttpCommand) -> Result<()> {
    match command {
        HttpCommand::Bind {
            item,
            base_url,
            header,
            template,
            field,
            allow_private,
        } => {
            let binding = HttpBinding {
                base_url,
                header,
                template,
                field,
                allow_private,
            };
            binding.validate()?;
            print_rpc(
                daemon,
                RpcRequest::HttpBindingSet {
                    auth: auth(cli)?,
                    id: item_id(&item),
                    binding: Some(binding),
                },
            )
            .await
        }
        HttpCommand::Unbind { item } => {
            print_rpc(
                daemon,
                RpcRequest::HttpBindingSet {
                    auth: auth(cli)?,
                    id: item_id(&item),
                    binding: None,
                },
            )
            .await
        }
        HttpCommand::Show { item } => {
            print_rpc(
                daemon,
                RpcRequest::HttpBindingGet {
                    auth: auth(cli)?,
                    id: item_id(&item),
                },
            )
            .await
        }
        HttpCommand::Proxy { item, listen } => {
            let backend = Backend::for_cli(cli, daemon)?;
            let proxy = LocalProxy::bind(listen, backend, vec![item_id(&item)]).await?;
            eprintln!(
                "KeyLease HTTP proxy for {item}: use {} as the API base URL (Ctrl-C to stop)",
                proxy.base_urls()[0]
            );
            proxy.serve().await
        }
    }
}

/// A loopback listener with one capability path per item.
pub(crate) struct LocalProxy {
    listener: tokio::net::TcpListener,
    state: ProxyState,
    base_urls: Vec<String>,
}

#[derive(Clone)]
struct ProxyState {
    backend: Backend,
    /// capability → item
    routes: Arc<BTreeMap<String, ItemId>>,
}

impl LocalProxy {
    pub(crate) async fn bind(
        listen: std::net::SocketAddr,
        backend: Backend,
        items: Vec<ItemId>,
    ) -> Result<Self> {
        if !listen.ip().is_loopback() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "the HTTP proxy listens on loopback only".into(),
            });
        }
        let listener = tokio::net::TcpListener::bind(listen).await.map_err(|_| {
            KeyLeaseError::InvalidRequest {
                reason: format!("cannot listen on {listen}"),
            }
        })?;
        let address = listener.local_addr().map_err(|_| KeyLeaseError::Storage)?;
        let mut routes = BTreeMap::new();
        let mut base_urls = Vec::new();
        for item in items {
            let mut bytes = [0_u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
            let capability = format!(
                "kl-{}",
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            base_urls.push(format!("http://{address}/{capability}"));
            routes.insert(capability, item);
        }
        Ok(Self {
            listener,
            state: ProxyState {
                backend,
                routes: Arc::new(routes),
            },
            base_urls,
        })
    }

    pub(crate) fn base_urls(&self) -> &[String] {
        &self.base_urls
    }

    pub(crate) async fn serve(self) -> Result<()> {
        let router = Router::new()
            .route("/{capability}", any(forward_root))
            .route("/{capability}/{*path}", any(forward))
            .with_state(self.state);
        axum::serve(self.listener, router)
            .await
            .map_err(|_| KeyLeaseError::Storage)
    }
}

async fn forward_root(
    state: State<ProxyState>,
    AxumPath(capability): AxumPath<String>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(
        state.0,
        capability,
        String::new(),
        method,
        uri,
        headers,
        body,
    )
    .await
}

async fn forward(
    state: State<ProxyState>,
    AxumPath((capability, path)): AxumPath<(String, String)>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(state.0, capability, path, method, uri, headers, body).await
}

async fn handle(
    state: ProxyState,
    capability: String,
    path: String,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(item) = state.routes.get(&capability).cloned() else {
        return (StatusCode::NOT_FOUND, "unknown KeyLease proxy path\n").into_response();
    };
    if body.len() > MAX_HTTP_BODY_BYTES {
        return keylease_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            &format!("KeyLease forwards bodies up to {MAX_HTTP_BODY_BYTES} bytes"),
            None,
        );
    }
    let mut target = format!("/{path}");
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    let request = HttpForwardRequest {
        item_id: item,
        method: method.as_str().to_owned(),
        path: target,
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body_b64: (!body.is_empty()).then(|| STANDARD.encode(&body)),
    };
    let outcome = state
        .backend
        .call(|auth| RpcRequest::HttpForward {
            auth,
            request: request.clone(),
        })
        .await;
    match outcome {
        Ok(value) => match serde_json::from_value::<HttpForwardResponse>(value) {
            Ok(response) => upstream_response(response),
            Err(_) => keylease_error(
                StatusCode::BAD_GATEWAY,
                "storage",
                "bad daemon response",
                None,
            ),
        },
        Err(KeyLeaseError::ApprovalRequired { approval_id }) => keylease_error(
            StatusCode::FORBIDDEN,
            "approval_required",
            "KeyLease is waiting for the user to approve this API use. Do not ask for the \
             credential; ask the user to approve it in KeyLease (`keylease approve`), then retry.",
            Some(&approval_id),
        ),
        Err(KeyLeaseError::Denied { reason }) => {
            keylease_error(StatusCode::FORBIDDEN, "denied", &reason, None)
        }
        Err(KeyLeaseError::NotFound { resource }) => keylease_error(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("{resource} not found"),
            None,
        ),
        Err(KeyLeaseError::InvalidRequest { reason }) => {
            keylease_error(StatusCode::BAD_REQUEST, "invalid_request", &reason, None)
        }
        Err(KeyLeaseError::VaultLocked { .. }) => keylease_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault_locked",
            "the KeyLease vault is locked",
            None,
        ),
        Err(_) => keylease_error(
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
            "KeyLease could not reach the API",
            None,
        ),
    }
}

fn upstream_response(response: HttpForwardResponse) -> Response {
    let body = STANDARD.decode(&response.body_b64).unwrap_or_default();
    let mut out = Response::new(Body::from(body));
    *out.status_mut() = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in response.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            out.headers_mut().append(name, value);
        }
    }
    out
}

/// A self-explanatory refusal: the agent reads the JSON and the
/// `x-keylease-decision` header and knows what to do next.
fn keylease_error(
    status: StatusCode,
    decision: &str,
    message: &str,
    approval: Option<&str>,
) -> Response {
    let mut body = json!({"error": decision, "message": message, "source": "keylease"});
    if let Some(approval) = approval {
        body["approval_id"] = json!(approval);
    }
    let mut response = (status, axum::Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(decision) {
        response.headers_mut().insert("x-keylease-decision", value);
    }
    if let Some(approval) = approval.and_then(|approval| HeaderValue::from_str(approval).ok()) {
        response
            .headers_mut()
            .insert("x-keylease-approval-id", approval);
    }
    response
}

/// `--http NAME=ITEM` bindings of `keylease run`.
pub(crate) fn parse_http_binding(binding: &str) -> Result<(String, ItemId)> {
    let invalid = || KeyLeaseError::InvalidRequest {
        reason: "use --http NAME=ITEM_ID or NAME=kl://PROJECT[/ENV]/ITEM".into(),
    };
    let (name, reference) = binding.split_once('=').ok_or_else(invalid)?;
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || reference.is_empty()
        || reference.contains('#')
    {
        return Err(invalid());
    }
    Ok((name.to_owned(), item_id(reference)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_bindings_parse_ids_and_names() {
        let (name, id) = parse_http_binding("STRIPE_API_BASE=kl://shop/production/Stripe").unwrap();
        assert_eq!(name, "STRIPE_API_BASE");
        assert_eq!(id.0, "ref:shop/production/Stripe");
        assert_eq!(parse_http_binding("X=item_1").unwrap().1.0, "item_1");
        for bad in ["=item_1", "1X=item_1", "X=", "X=kl://a/b#c"] {
            assert!(parse_http_binding(bad).is_err(), "{bad}");
        }
    }
}
