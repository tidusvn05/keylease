//! The intercepting mode of the HTTP credential broker (ADR 0007, phase 2):
//! `keylease run --proxy ITEM -- CMD` gives the program `HTTPS_PROXY` and a
//! certificate bundle that trusts a certificate authority made for this run.
//!
//! - A `CONNECT` to the host and port of a bound item is answered with a
//!   certificate for that host signed by the run's CA; each request inside is
//!   forwarded through the daemon like the base-URL mode, so the program can
//!   keep its real API URL and any placeholder credential.
//! - A `CONNECT` to any other host is tunneled untouched (no decryption).
//!
//! The CA key exists only in this process's memory and the bundle files are
//! removed when the run ends. The proxy URL carries a random password, so other
//! local processes cannot use it.

use super::*;
use crate::backend::Backend;
use axum::body::Bytes;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use hyper::{
    Method, Request, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use keylease_service::{HttpBinding, MAX_HTTP_BODY_BYTES};
use std::collections::HashMap;
use std::sync::Mutex;

type BoxBody = axum::body::Body;

/// One bound item reachable through the proxy.
#[derive(Clone, Debug)]
struct Route {
    host: String,
    port: u16,
    base_path: String,
    item: ItemId,
}

struct Authority {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pem: String,
    leaves: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

struct MitmState {
    backend: Backend,
    password: String,
    routes: Vec<Route>,
    authority: Authority,
}

pub(crate) struct MitmProxy {
    listener: tokio::net::TcpListener,
    state: Arc<MitmState>,
    /// Holds the CA certificate and the bundle; removed on drop.
    directory: tempfile::TempDir,
}

/// The environment a program needs to use the proxy and trust its CA.
pub(crate) struct ProxyEnvironment {
    pub(crate) variables: Vec<(String, String)>,
}

fn invalid(reason: impl Into<String>) -> KeyLeaseError {
    KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    }
}

/// (year, month, day) `offset_days` from today, for certificate validity.
fn day(offset_days: i64) -> (i32, u8, u8) {
    use chrono::Datelike;
    let day = (Utc::now() + Duration::days(offset_days)).date_naive();
    (day.year(), day.month() as u8, day.day() as u8)
}

fn set_validity(params: &mut rcgen::CertificateParams) {
    let (year, month, date) = day(-1);
    params.not_before = rcgen::date_time_ymd(year, month, date);
    let (year, month, date) = day(7);
    params.not_after = rcgen::date_time_ymd(year, month, date);
}

impl Authority {
    fn generate() -> Result<Self> {
        let key = rcgen::KeyPair::generate().map_err(|_| KeyLeaseError::Crypto)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|_| KeyLeaseError::Crypto)?;
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, "KeyLease run CA (this run only)");
        name.push(rcgen::DnType::OrganizationName, "KeyLease");
        params.distinguished_name = name;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        set_validity(&mut params);
        let certificate = params
            .self_signed(&key)
            .map_err(|_| KeyLeaseError::Crypto)?;
        Ok(Self {
            pem: certificate.pem(),
            issuer: rcgen::Issuer::new(params, key),
            leaves: Mutex::default(),
        })
    }

    fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(config) = self
            .leaves
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .get(host)
        {
            return Ok(config.clone());
        }
        let key = rcgen::KeyPair::generate().map_err(|_| KeyLeaseError::Crypto)?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])
            .map_err(|_| KeyLeaseError::Crypto)?;
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, host);
        params.distinguished_name = name;
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params);
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| KeyLeaseError::Crypto)?;
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| KeyLeaseError::Crypto)?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.der().clone()], key_der)
        .map_err(|_| KeyLeaseError::Crypto)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.leaves
            .lock()
            .map_err(|_| KeyLeaseError::Storage)?
            .insert(host.to_owned(), config.clone());
        Ok(config)
    }
}

/// The system trust store as PEM, so the bundle trusts everything the system
/// does plus the run's CA.
fn system_roots_pem() -> Option<String> {
    let candidates = [
        std::env::var("SSL_CERT_FILE").ok(),
        Some("/etc/ssl/certs/ca-certificates.crt".into()),
        Some("/etc/pki/tls/certs/ca-bundle.crt".into()),
        Some("/etc/ssl/cert.pem".into()),
        Some("/etc/ssl/ca-bundle.pem".into()),
    ];
    candidates.into_iter().flatten().find_map(|path| {
        fs::read_to_string(&path)
            .ok()
            .filter(|text| text.contains("BEGIN CERTIFICATE"))
    })
}

impl MitmProxy {
    /// Looks up each item's binding and starts listening on loopback.
    pub(crate) async fn bind(backend: Backend, items: Vec<ItemId>) -> Result<Self> {
        let mut routes = Vec::new();
        for item in items {
            let value = backend
                .call(|auth| RpcRequest::HttpBindingGet {
                    auth,
                    id: item.clone(),
                })
                .await?;
            let binding: Option<HttpBinding> =
                serde_json::from_value(value).map_err(|_| KeyLeaseError::Storage)?;
            let binding = binding.ok_or_else(|| {
                invalid(format!(
                    "{} has no HTTP binding; set one with `keylease http bind`",
                    item.0.trim_start_matches("ref:")
                ))
            })?;
            let url = binding.validate()?;
            routes.push(Route {
                host: url
                    .host_str()
                    .unwrap_or_default()
                    .trim_matches(['[', ']'])
                    .to_ascii_lowercase(),
                port: url.port_or_known_default().unwrap_or(443),
                base_path: url.path().trim_end_matches('/').to_owned(),
                item,
            });
        }
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|_| KeyLeaseError::Storage)?;
        let mut password = [0_u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut password);
        let password = password.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = tempfile::Builder::new()
            .prefix("keylease-proxy-")
            .tempdir()
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(Self {
            listener,
            state: Arc::new(MitmState {
                backend,
                password,
                routes,
                authority: Authority::generate()?,
            }),
            directory,
        })
    }

    /// Writes the CA and the bundle, and returns the variables for the child.
    pub(crate) fn environment(&self) -> Result<ProxyEnvironment> {
        use std::os::unix::fs::OpenOptionsExt;
        let write = |name: &str, text: &str| -> Result<String> {
            let path = self.directory.path().join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| KeyLeaseError::Storage)?;
            file.write_all(text.as_bytes())
                .map_err(|_| KeyLeaseError::Storage)?;
            Ok(path.display().to_string())
        };
        let ca = write("keylease-run-ca.pem", &self.state.authority.pem)?;
        let bundle = match system_roots_pem() {
            Some(mut roots) => {
                if !roots.ends_with('\n') {
                    roots.push('\n');
                }
                roots.push_str(&self.state.authority.pem);
                Some(write("ca-bundle.pem", &roots)?)
            }
            None => {
                eprintln!(
                    "KeyLease: no system CA bundle found; only Node.js (NODE_EXTRA_CA_CERTS) \
                     will trust the proxy. Set SSL_CERT_FILE to your CA bundle."
                );
                None
            }
        };
        let address = self
            .listener
            .local_addr()
            .map_err(|_| KeyLeaseError::Storage)?;
        let proxy = format!("http://keylease:{}@{address}", self.state.password);
        let mut variables = vec![
            ("HTTPS_PROXY".to_owned(), proxy.clone()),
            ("https_proxy".to_owned(), proxy),
            ("NO_PROXY".to_owned(), "localhost,127.0.0.1,::1".to_owned()),
            ("no_proxy".to_owned(), "localhost,127.0.0.1,::1".to_owned()),
            // Node only reads proxy variables with this set (Node 24+).
            ("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()),
            ("NODE_EXTRA_CA_CERTS".to_owned(), ca),
        ];
        if let Some(bundle) = bundle {
            for name in [
                "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "GIT_SSL_CAINFO",
                "DENO_CERT",
                "AWS_CA_BUNDLE",
            ] {
                variables.push((name.to_owned(), bundle.clone()));
            }
        }
        Ok(ProxyEnvironment { variables })
    }

    /// Serves until the returned handle is dropped or aborted. The temporary
    /// directory is kept alive by the returned guard.
    pub(crate) fn spawn(self) -> (tokio::task::JoinHandle<()>, tempfile::TempDir) {
        let Self {
            listener,
            state,
            directory,
        } = self;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| proxy_request(state.clone(), request));
                    let _ = http1::Builder::new()
                        .preserve_header_case(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades()
                        .await;
                });
            }
        });
        (task, directory)
    }
}

fn simple(status: StatusCode, text: &str) -> hyper::Response<BoxBody> {
    let mut response = hyper::Response::new(BoxBody::from(text.to_owned()));
    *response.status_mut() = status;
    response
}

fn authorized(state: &MitmState, request: &Request<Incoming>) -> bool {
    let expected = STANDARD.encode(format!("keylease:{}", state.password));
    request
        .headers()
        .get("proxy-authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .is_some_and(|value| subtle_eq(value.trim().as_bytes(), expected.as_bytes()))
}

fn subtle_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

async fn proxy_request(
    state: Arc<MitmState>,
    request: Request<Incoming>,
) -> std::result::Result<hyper::Response<BoxBody>, std::convert::Infallible> {
    if !authorized(&state, &request) {
        let mut response = simple(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "KeyLease proxy\n",
        );
        response.headers_mut().insert(
            "proxy-authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"keylease\""),
        );
        return Ok(response);
    }
    if request.method() != Method::CONNECT {
        return Ok(simple(
            StatusCode::METHOD_NOT_ALLOWED,
            "the KeyLease proxy only handles HTTPS (CONNECT)\n",
        ));
    }
    let Some(authority) = request.uri().authority().cloned() else {
        return Ok(simple(StatusCode::BAD_REQUEST, "CONNECT needs host:port\n"));
    };
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    let route = state
        .routes
        .iter()
        .find(|route| route.host == host && route.port == port)
        .cloned();
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(request).await else {
            return;
        };
        let io = TokioIo::new(upgraded);
        match route {
            Some(route) => intercept(state, route, io).await,
            None => tunnel(io, &host, port).await,
        }
    });
    Ok(hyper::Response::new(BoxBody::empty()))
}

/// Passes an unbound host's traffic through without decrypting it.
async fn tunnel(mut io: TokioIo<hyper::upgrade::Upgraded>, host: &str, port: u16) {
    if let Ok(mut upstream) = tokio::net::TcpStream::connect((host, port)).await {
        let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
    }
}

/// Terminates TLS for a bound host and forwards each request through the
/// daemon.
async fn intercept(state: Arc<MitmState>, route: Route, io: TokioIo<hyper::upgrade::Upgraded>) {
    let Ok(config) = state.authority.server_config(&route.host) else {
        return;
    };
    let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(io).await else {
        return;
    };
    let service = service_fn(move |request: Request<Incoming>| {
        let state = state.clone();
        let route = route.clone();
        async move { Ok::<_, std::convert::Infallible>(forward(&state, &route, request).await) }
    });
    let _ = http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(tls), service)
        .await;
}

async fn forward(
    state: &MitmState,
    route: &Route,
    request: Request<Incoming>,
) -> hyper::Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let below = if route.base_path.is_empty() {
        Some(path)
    } else {
        path.strip_prefix(&route.base_path)
            .filter(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    let Some(rest) = below else {
        return crate::http_proxy::keylease_error(
            StatusCode::FORBIDDEN,
            "outside_binding",
            &format!(
                "KeyLease only adds the credential below {}; this path is outside it",
                if route.base_path.is_empty() {
                    "/"
                } else {
                    &route.base_path
                }
            ),
            None,
        );
    };
    let mut target = if rest.is_empty() {
        "/".to_owned()
    } else {
        rest.to_owned()
    };
    if let Some(query) = parts.uri.query() {
        target.push('?');
        target.push_str(query);
    }
    let body = match http_body_util::Limited::new(body, MAX_HTTP_BODY_BYTES + 1)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };
    crate::http_proxy::forward_request(
        &state.backend,
        route.item.clone(),
        &parts.method,
        target,
        &parts.headers,
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that trusts only the run's CA completes a TLS handshake with
    /// the certificate made for the host it asked for.
    #[tokio::test]
    async fn host_certificates_chain_to_the_run_ca() {
        let authority = Authority::generate().unwrap();
        let server_config = authority.server_config("api.example.com").unwrap();
        // Cached per host.
        assert!(Arc::ptr_eq(
            &server_config,
            &authority.server_config("api.example.com").unwrap()
        ));
        let mut roots = rustls::RootCertStore::empty();
        let der = authority_der(&authority.pem);
        roots.add(der).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            tokio_rustls::TlsAcceptor::from(server_config)
                .accept(server_io)
                .await
                .is_ok()
        });
        let name = rustls::pki_types::ServerName::try_from("api.example.com").unwrap();
        let client = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(name, client_io)
            .await;
        assert!(client.is_ok(), "{:?}", client.err());
        assert!(server.await.unwrap());
    }

    fn authority_der(pem: &str) -> rustls::pki_types::CertificateDer<'static> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        rustls::pki_types::CertificateDer::from(STANDARD.decode(body).unwrap())
    }

    #[test]
    fn the_proxy_password_is_compared_in_constant_time_shape() {
        assert!(subtle_eq(b"abc", b"abc"));
        assert!(!subtle_eq(b"abc", b"abd"));
        assert!(!subtle_eq(b"abc", b"abcd"));
    }
}
