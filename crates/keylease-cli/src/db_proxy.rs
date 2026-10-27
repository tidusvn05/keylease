//! A local PostgreSQL proxy that never holds the database password (ADR 0005).
//!
//! Clients (`psql`, `pg_dump`, an ORM) connect to a private Unix socket. The
//! proxy connects to the real server, preferring TLS, and when the server asks
//! for SCRAM-SHA-256 it forwards the challenge to the KeyLease service, which
//! answers with a proof computed from the stored password. After that the
//! proxy only relays bytes.

use super::*;
use crate::backend::{Backend, listener_owner_uid};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use std::sync::Arc as StdArc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;
const CANCEL_REQUEST: u32 = 80_877_102;
const PROTOCOL_3: u32 = 196_608;
const MAX_STARTUP_BYTES: usize = 10_000;
const MAX_AUTH_MESSAGE_BYTES: usize = 64 * 1024;

/// How long a connection waits for an approval when `--wait-approval` is not
/// set; the client simply blocks meanwhile.
pub(crate) const DEFAULT_CONNECT_WAIT_SECONDS: u64 = 120;

#[derive(Subcommand)]
pub(crate) enum DbCommand {
    /// Serve a local socket for any PostgreSQL client until interrupted.
    Proxy {
        item_id: String,
        /// Directory for the `.s.PGSQL.<port>` socket; private temporary by default.
        #[arg(long)]
        socket_dir: Option<PathBuf>,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Run `psql` through a private, single-use proxy.
    #[command(trailing_var_arg = true)]
    Psql {
        item_id: String,
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
        #[command(flatten)]
        tls: TlsArgs,
    },
    /// Run any command with PGHOST/PGPORT/PGUSER/PGDATABASE and DATABASE_URL
    /// pointing at a private, single-use proxy.
    #[command(trailing_var_arg = true)]
    Exec {
        item_id: String,
        #[arg(allow_hyphen_values = true, required = true)]
        command: Vec<String>,
        #[command(flatten)]
        tls: TlsArgs,
    },
}

#[derive(Args, Clone, Default)]
pub(crate) struct TlsArgs {
    /// Allow an unencrypted connection to a non-loopback server.
    #[arg(long)]
    insecure_plaintext: bool,
    /// PEM file with the CA that signed the server certificate, in addition to
    /// the public web roots.
    #[arg(long)]
    tls_ca: Option<PathBuf>,
}

impl TlsArgs {
    pub(crate) fn with_ca(tls_ca: Option<PathBuf>) -> Self {
        Self {
            insecure_plaintext: false,
            tls_ca,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Target {
    item_id: ItemId,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) database: String,
    pub(crate) username: String,
}

trait Upstream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Upstream for T {}

pub(crate) async fn db_command(cli: &Cli, daemon: &Path, command: DbCommand) -> Result<()> {
    let backend = Backend::for_cli(cli, daemon)?;
    match command {
        DbCommand::Proxy {
            item_id,
            socket_dir,
            tls,
        } => {
            let target = target(&backend, &item_id).await?;
            let (listener, directory, _temporary) = bind(socket_dir, target.port)?;
            println!(
                "PGHOST={dir}; PGPORT={port}; PGUSER={user}; PGDATABASE={db}; export PGHOST PGPORT PGUSER PGDATABASE;",
                dir = shell_quote(&directory.to_string_lossy()),
                port = target.port,
                user = shell_quote(&target.username),
                db = shell_quote(&target.database),
            );
            io::stdout().flush().map_err(|_| KeyLeaseError::Storage)?;
            eprintln!(
                "keylease db proxy: {}:{} via {}",
                target.host,
                target.port,
                directory.display()
            );
            tokio::select! {
                () = serve(listener, backend, target, tls) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            Ok(())
        }
        DbCommand::Psql { item_id, args, tls } => {
            run_with_proxy(backend, &item_id, tls, "psql", args).await
        }
        DbCommand::Exec {
            item_id,
            mut command,
            tls,
        } => {
            let program = command.remove(0);
            run_with_proxy(backend, &item_id, tls, &program, command).await
        }
    }
}

pub(crate) async fn target(backend: &Backend, item_id: &str) -> Result<Target> {
    let value = backend
        .call(|auth| RpcRequest::DbTarget {
            auth,
            id: ItemId(item_id.into()),
        })
        .await?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(KeyLeaseError::Storage)
    };
    Ok(Target {
        item_id: ItemId(item_id.into()),
        host: field("host")?,
        port: value
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or(KeyLeaseError::Storage)?,
        database: field("database")?,
        username: field("username")?,
    })
}

pub(crate) fn bind(
    directory: Option<PathBuf>,
    port: u16,
) -> Result<(UnixListener, PathBuf, Option<tempfile::TempDir>)> {
    let (directory, temporary) = match directory {
        Some(directory) => {
            fs::create_dir_all(&directory).map_err(|_| KeyLeaseError::Storage)?;
            (directory, None)
        }
        None => {
            let temporary = tempfile::Builder::new()
                .prefix("keylease-db-")
                .tempdir()
                .map_err(|_| KeyLeaseError::Storage)?;
            (temporary.path().to_path_buf(), Some(temporary))
        }
    };
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| KeyLeaseError::Storage)?;
    let socket = directory.join(format!(".s.PGSQL.{port}"));
    if socket.exists() {
        let metadata = fs::symlink_metadata(&socket).map_err(|_| KeyLeaseError::Storage)?;
        if !metadata.file_type().is_socket() {
            return Err(KeyLeaseError::Denied {
                reason: "refusing to replace a non-socket path".into(),
            });
        }
        fs::remove_file(&socket).map_err(|_| KeyLeaseError::Storage)?;
    }
    let listener = UnixListener::bind(&socket).map_err(|_| KeyLeaseError::Storage)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok((listener, directory, temporary))
}

async fn run_with_proxy(
    backend: Backend,
    item_id: &str,
    tls: TlsArgs,
    program: &str,
    args: Vec<String>,
) -> Result<()> {
    let target = target(&backend, item_id).await?;
    let (listener, directory, temporary) = bind(None, target.port)?;
    let server = tokio::spawn(serve(listener, backend, target.clone(), tls));
    let url = format!(
        "postgresql://{user}@/{db}?host={host}&port={port}",
        user = url_component(&target.username),
        db = url_component(&target.database),
        host = url_component(&directory.to_string_lossy()),
        port = target.port,
    );
    let status = tokio::process::Command::new(program)
        .args(&args)
        .env("PGHOST", &directory)
        .env("PGPORT", target.port.to_string())
        .env("PGUSER", &target.username)
        .env("PGDATABASE", &target.database)
        .env("PGSSLMODE", "disable")
        .env("DATABASE_URL", url)
        .env_remove("PGPASSWORD")
        .status()
        .await
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: format!("cannot run {program}"),
        })?;
    server.abort();
    drop(temporary);
    std::process::exit(status.code().unwrap_or(1));
}

pub(crate) async fn serve(listener: UnixListener, backend: Backend, target: Target, tls: TlsArgs) {
    let owner_uid = listener_owner_uid(&listener);
    let connector = match tls_connector(tls.tls_ca.as_deref()) {
        Ok(connector) => connector,
        Err(error) => {
            eprintln!("keylease db proxy: {}", describe(&error));
            return;
        }
    };
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        if stream.peer_cred().map(|cred| cred.uid()).ok() != Some(owner_uid) {
            eprintln!("keylease db proxy: rejected a peer with an unexpected uid");
            continue;
        }
        let (backend, target, connector) = (backend.clone(), target.clone(), connector.clone());
        let insecure = tls.insecure_plaintext;
        tokio::spawn(async move {
            if let Err(message) = session(stream, &backend, &target, connector, insecure).await {
                eprintln!("keylease db proxy: {message}");
            }
        });
    }
}

fn tls_connector(ca: Option<&Path>) -> Result<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca {
        let pem = fs::read(path).map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "cannot read --tls-ca".into(),
        })?;
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        for certificate in CertificateDer::pem_slice_iter(&pem) {
            let certificate = certificate.map_err(|_| KeyLeaseError::InvalidRequest {
                reason: "invalid certificate in --tls-ca".into(),
            })?;
            roots
                .add(certificate)
                .map_err(|_| KeyLeaseError::InvalidRequest {
                    reason: "invalid certificate in --tls-ca".into(),
                })?;
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(StdArc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| KeyLeaseError::Storage)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(StdArc::new(config)))
}

fn describe(error: &KeyLeaseError) -> String {
    match error {
        KeyLeaseError::ApprovalRequired { approval_id } => {
            format!("approval {approval_id} was not decided in time")
        }
        KeyLeaseError::VaultLocked { .. } => "the vault is locked; unlock KeyLease".into(),
        KeyLeaseError::Denied { reason } => format!("denied: {reason}"),
        KeyLeaseError::InvalidRequest { reason } => reason.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "request failed".into()),
    }
}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S, limit: usize) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if !(4..=limit).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad packet length",
        ));
    }
    let mut body = vec![0_u8; length - 4];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Reads a tagged backend message: (tag, body).
async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut tag = [0_u8; 1];
    stream.read_exact(&mut tag).await?;
    let body = read_packet(stream, MAX_AUTH_MESSAGE_BYTES).await?;
    Ok((tag[0], body))
}

fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(tag);
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn error_response(text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (code, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', "28000"),
        (b'M', text),
    ] {
        body.push(code);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    message(b'E', &body)
}

/// Parses StartupMessage parameters (after the protocol version).
fn startup_parameters(body: &[u8]) -> Option<Vec<(String, String)>> {
    let mut parts = body.split(|byte| *byte == 0);
    let mut parameters = Vec::new();
    loop {
        let key = parts.next()?;
        if key.is_empty() {
            return Some(parameters);
        }
        let value = parts.next()?;
        parameters.push((
            String::from_utf8(key.to_vec()).ok()?,
            String::from_utf8(value.to_vec()).ok()?,
        ));
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

async fn session(
    mut client: UnixStream,
    backend: &Backend,
    target: &Target,
    connector: tokio_rustls::TlsConnector,
    insecure_plaintext: bool,
) -> std::result::Result<(), String> {
    let io = |error: io::Error| error.to_string();
    // Startup: refuse encryption on the local socket, pass cancels through.
    let startup = loop {
        let body = read_packet(&mut client, MAX_STARTUP_BYTES)
            .await
            .map_err(io)?;
        let code = u32::from_be_bytes(body.get(..4).ok_or("short startup")?.try_into().unwrap());
        match code {
            SSL_REQUEST | GSSENC_REQUEST => client.write_all(b"N").await.map_err(io)?,
            CANCEL_REQUEST => {
                let mut upstream = TcpStream::connect((target.host.as_str(), target.port))
                    .await
                    .map_err(io)?;
                let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
                packet.extend_from_slice(&body);
                upstream.write_all(&packet).await.map_err(io)?;
                return Ok(());
            }
            PROTOCOL_3 => break body,
            _ => {
                let _ = client
                    .write_all(&error_response("unsupported frontend protocol"))
                    .await;
                return Err("unsupported frontend protocol".into());
            }
        }
    };
    let parameters = startup_parameters(&startup[4..]).ok_or("malformed startup message")?;
    if parameters.iter().any(|(key, _)| key == "replication") {
        let _ = client
            .write_all(&error_response("replication connections are not proxied"))
            .await;
        return Err("replication refused".into());
    }
    let database = parameters
        .iter()
        .find(|(key, _)| key == "database")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| target.database.clone());

    let upstream = match connect_upstream(target, connector, insecure_plaintext).await {
        Ok(upstream) => upstream,
        Err(text) => {
            let _ = client.write_all(&error_response(&text)).await;
            return Err(text);
        }
    };
    let mut upstream = upstream;

    // Forward the client's options, but always as the item's role.
    let mut body = PROTOCOL_3.to_be_bytes().to_vec();
    for (key, value) in parameters
        .iter()
        .filter(|(key, _)| key != "user" && key != "database")
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .chain([
            ("user", target.username.as_str()),
            ("database", database.as_str()),
        ])
    {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    upstream.write_all(&packet).await.map_err(io)?;

    if let Err(text) = authenticate(&mut upstream, backend, target, &database).await {
        let _ = client.write_all(&error_response(&text)).await;
        return Err(text);
    }
    client
        .write_all(&message(b'R', &0_u32.to_be_bytes()))
        .await
        .map_err(io)?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(io)?;
    Ok(())
}

async fn connect_upstream(
    target: &Target,
    connector: tokio_rustls::TlsConnector,
    insecure_plaintext: bool,
) -> std::result::Result<Box<dyn Upstream>, String> {
    let mut tcp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| "timed out connecting to the database".to_owned())?
    .map_err(|error| format!("cannot connect to the database: {error}"))?;
    let mut request = 8_u32.to_be_bytes().to_vec();
    request.extend_from_slice(&SSL_REQUEST.to_be_bytes());
    tcp.write_all(&request).await.map_err(|e| e.to_string())?;
    let mut answer = [0_u8; 1];
    tcp.read_exact(&mut answer)
        .await
        .map_err(|e| e.to_string())?;
    if answer[0] == b'S' {
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|_| "invalid database host name for TLS".to_owned())?;
        let stream = connector
            .connect(name, tcp)
            .await
            .map_err(|error| format!("TLS to the database failed: {error}"))?;
        return Ok(Box::new(stream));
    }
    if is_loopback(&target.host) || insecure_plaintext {
        return Ok(Box::new(tcp));
    }
    Err("the database does not offer TLS; pass --insecure-plaintext to allow it".into())
}

/// Runs the backend authentication exchange until AuthenticationOk.
async fn authenticate(
    upstream: &mut Box<dyn Upstream>,
    backend: &Backend,
    target: &Target,
    database: &str,
) -> std::result::Result<(), String> {
    let io = |error: io::Error| error.to_string();
    let mut expected_signature: Option<String> = None;
    let mut client_first_bare = String::new();
    loop {
        let (tag, body) = read_message(upstream).await.map_err(io)?;
        if tag == b'E' {
            return Err(backend_error(&body));
        }
        if tag != b'R' || body.len() < 4 {
            return Err("unexpected message during authentication".into());
        }
        let code = u32::from_be_bytes(body[..4].try_into().unwrap());
        let payload = &body[4..];
        match code {
            0 => return Ok(()),
            10 => {
                let offers_scram = payload
                    .split(|byte| *byte == 0)
                    .any(|mechanism| mechanism == b"SCRAM-SHA-256");
                if !offers_scram {
                    return Err("the server does not offer SCRAM-SHA-256".into());
                }
                let mut nonce = [0_u8; 18];
                rand::rng().fill_bytes(&mut nonce);
                client_first_bare = format!("n=,r={}", STANDARD.encode(nonce));
                let first = format!("n,,{client_first_bare}");
                let mut response = b"SCRAM-SHA-256\0".to_vec();
                response.extend_from_slice(&(first.len() as u32).to_be_bytes());
                response.extend_from_slice(first.as_bytes());
                upstream
                    .write_all(&message(b'p', &response))
                    .await
                    .map_err(io)?;
            }
            11 => {
                let server_first =
                    std::str::from_utf8(payload).map_err(|_| "invalid SCRAM challenge")?;
                let answer = backend
                    .call(|auth| RpcRequest::DbScram {
                        auth,
                        id: target.item_id.clone(),
                        database: database.into(),
                        client_first_bare: client_first_bare.clone(),
                        server_first: server_first.into(),
                    })
                    .await
                    .map_err(|error| describe(&error))?;
                let client_final = answer
                    .get("client_final")
                    .and_then(Value::as_str)
                    .ok_or("invalid SCRAM answer")?;
                expected_signature = answer
                    .get("server_signature")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                upstream
                    .write_all(&message(b'p', client_final.as_bytes()))
                    .await
                    .map_err(io)?;
            }
            12 => {
                let server_final =
                    std::str::from_utf8(payload).map_err(|_| "invalid SCRAM final")?;
                let verified = expected_signature
                    .as_deref()
                    .is_some_and(|expected| server_final == format!("v={expected}"));
                if !verified {
                    return Err("the database server failed SCRAM verification".into());
                }
            }
            3 | 5 => {
                return Err(
                    "the server asked for a password-revealing method; configure it for \
                     scram-sha-256"
                        .into(),
                );
            }
            _ => return Err(format!("unsupported authentication request {code}")),
        }
    }
}

fn backend_error(body: &[u8]) -> String {
    body.split(|byte| *byte == 0)
        .find_map(|field| field.strip_prefix(b"M"))
        .map(|text| String::from_utf8_lossy(text).into_owned())
        .unwrap_or_else(|| "the database refused the connection".into())
}

fn url_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_parameters_parse_and_reject_truncation() {
        let body = b"user\0alice\0database\0app\0\0";
        assert_eq!(
            startup_parameters(body).unwrap(),
            vec![
                ("user".into(), "alice".into()),
                ("database".into(), "app".into())
            ]
        );
        assert!(startup_parameters(b"user\0alice").is_none());
    }

    #[test]
    fn errors_and_urls_are_encoded() {
        let encoded = error_response("nope");
        assert_eq!(encoded[0], b'E');
        assert_eq!(backend_error(&encoded[5..]), "nope");
        assert_eq!(url_component("/tmp/a b"), "%2Ftmp%2Fa%20b");
        assert!(is_loopback("127.0.0.1") && is_loopback("::1") && !is_loopback("db.example"));
    }
}
