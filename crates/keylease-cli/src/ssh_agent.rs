//! An OpenSSH agent whose keys never leave the KeyLease service (ADR 0005).
//!
//! This process speaks the agent protocol to `ssh`, `git` and `ssh-keygen`
//! and forwards only two questions to the daemon: which public keys exist,
//! and "sign these bytes with that key". It never holds a private key, so an
//! agent CLI that can run `ssh` still cannot read one. Each signature is a
//! policy decision in the daemon and may wait for an approval.
//!
//! It relays OpenSSH's `session-bind@openssh.com` records with each sign
//! request, so the daemon knows (and verifies) which host a login is for.
//! With `--cert`, it also offers a short-lived certificate: it generates a key
//! for this agent's lifetime, has the daemon's CA item certify it, and signs
//! with that key itself. That key is the only one this process holds; it is
//! worth nothing once the certificate expires.

use super::*;
use crate::backend::{Backend, listener_owner_uid};
use base64::{Engine, engine::general_purpose::STANDARD};
use keylease_service::{MAX_SESSION_BINDS, SshSessionBind};
use ssh_key::{Algorithm, Certificate, PrivateKey, rand_core::OsRng};
use std::os::unix::fs::DirBuilderExt;
use tokio::sync::Mutex;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// A certificate is renewed when it has less than this left.
const CERT_RENEW_SECONDS: i64 = 30;

/// Largest agent message accepted. Real requests are a few kilobytes.
const MAX_AGENT_MESSAGE_BYTES: usize = 256 * 1024;

/// How long a sign request waits for an approval when `--wait-approval` is
/// not set. `ssh` simply blocks meanwhile, which is the approval UX.
pub(crate) const DEFAULT_SIGN_WAIT_SECONDS: u64 = 120;

/// Binds an agent socket in a fresh private directory.
pub(crate) fn bind(
    path: Option<PathBuf>,
) -> Result<(UnixListener, PathBuf, Option<tempfile::TempDir>)> {
    let (socket, temporary) = match path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|_| KeyLeaseError::Storage)?;
            }
            if path.exists() {
                let metadata = fs::symlink_metadata(&path).map_err(|_| KeyLeaseError::Storage)?;
                if !metadata.file_type().is_socket() {
                    return Err(KeyLeaseError::Denied {
                        reason: "refusing to replace a non-socket path".into(),
                    });
                }
                fs::remove_file(&path).map_err(|_| KeyLeaseError::Storage)?;
            }
            (path, None)
        }
        None => {
            let directory = tempfile::Builder::new()
                .prefix("keylease-ssh-")
                .tempdir()
                .map_err(|_| KeyLeaseError::Storage)?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .map_err(|_| KeyLeaseError::Storage)?;
            (directory.path().join("agent.sock"), Some(directory))
        }
    };
    let listener = UnixListener::bind(&socket).map_err(|_| KeyLeaseError::Storage)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| KeyLeaseError::Storage)?;
    Ok((listener, socket, temporary))
}

/// What `--cert` asks for: a certificate from this CA item.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct CertArgs {
    /// Offer a short-lived certificate from this SSH CA item (an SSH key item
    /// with a `ca_principals` field), before the vault's keys.
    #[arg(long = "cert", env = "KEYLEASE_SSH_CERT", value_name = "CA_ITEM_ID")]
    ca: Option<String>,
    /// A principal (login name) for the certificate; repeatable. Default: all
    /// the CA's principals.
    #[arg(long = "principal")]
    principals: Vec<String>,
    /// Certificate lifetime in seconds (default 300).
    #[arg(long)]
    cert_ttl: Option<u64>,
}

/// The current certificate and the key it certifies.
struct Issued {
    key: PrivateKey,
    blob: Vec<u8>,
    key_id: String,
    valid_before: chrono::DateTime<Utc>,
}

/// Issues certificates on demand and renews them before they expire.
struct CertSource {
    args: CertArgs,
    ca: String,
    issued: Mutex<Option<Issued>>,
}

impl CertSource {
    /// The certificate to offer, issuing a fresh one if needed. An issue that
    /// fails (denied, not decided in time) is reported and skipped, so the
    /// vault's own keys are still offered.
    async fn current(&self, backend: &Backend) -> Option<(Vec<u8>, String)> {
        let mut issued = self.issued.lock().await;
        let fresh = issued.as_ref().is_some_and(|issued| {
            issued.valid_before - Utc::now() > chrono::Duration::seconds(CERT_RENEW_SECONDS)
        });
        if !fresh {
            *issued = self
                .issue(backend)
                .await
                .map_err(|error| report(&error))
                .ok();
        }
        issued
            .as_ref()
            .map(|issued| (issued.blob.clone(), issued.key_id.clone()))
    }

    async fn issue(&self, backend: &Backend) -> Result<Issued> {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|_| KeyLeaseError::Crypto)?;
        let public_key = key
            .public_key()
            .to_openssh()
            .map_err(|_| KeyLeaseError::Crypto)?;
        let value = backend
            .call(|auth| RpcRequest::SshIssueCert {
                auth,
                id: ItemId(self.ca.clone()),
                public_key: public_key.clone(),
                principals: self.args.principals.clone(),
                ttl_seconds: self.args.cert_ttl,
            })
            .await?;
        let certificate = value
            .get("certificate")
            .and_then(Value::as_str)
            .and_then(|text| Certificate::from_openssh(text).ok())
            .filter(|certificate| certificate.public_key() == key.public_key().key_data())
            .ok_or(KeyLeaseError::Crypto)?;
        let valid_before = chrono::DateTime::from_timestamp(certificate.valid_before() as i64, 0)
            .ok_or(KeyLeaseError::Crypto)?;
        eprintln!(
            "keylease ssh-agent: certificate for {} until {}",
            certificate.valid_principals().join(", "),
            valid_before
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S")
        );
        Ok(Issued {
            blob: certificate.to_bytes().map_err(|_| KeyLeaseError::Crypto)?,
            key_id: certificate.key_id().to_owned(),
            key,
            valid_before,
        })
    }

    /// Signs with the certified key if `blob` is the current certificate.
    async fn sign(&self, blob: &[u8], data: &[u8]) -> Option<Option<Vec<u8>>> {
        let issued = self.issued.lock().await;
        let issued = issued.as_ref().filter(|issued| issued.blob == blob)?;
        let signature: ssh_key::Signature = match signature::Signer::try_sign(&issued.key, data) {
            Ok(signature) => signature,
            Err(_) => return Some(None),
        };
        Some(Vec::<u8>::try_from(signature).ok())
    }
}

/// Accepts agent connections until the listener is dropped.
pub(crate) async fn serve(listener: UnixListener, backend: Backend) {
    serve_with(listener, backend, CertArgs::default()).await;
}

/// `serve`, also offering a certificate when `cert` names a CA item.
pub(crate) async fn serve_with(listener: UnixListener, backend: Backend, cert: CertArgs) {
    let certs = cert.ca.clone().map(|ca| {
        Arc::new(CertSource {
            args: cert,
            ca,
            issued: Mutex::new(None),
        })
    });
    let owner_uid = listener_owner_uid(&listener);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        if stream.peer_cred().map(|cred| cred.uid()).ok() != Some(owner_uid) {
            eprintln!("keylease ssh-agent: rejected a peer with an unexpected uid");
            continue;
        }
        let backend = backend.clone();
        let certs = certs.clone();
        tokio::spawn(async move {
            let _ = connection(stream, &backend, certs.as_deref()).await;
        });
    }
}

async fn connection(
    mut stream: UnixStream,
    backend: &Backend,
    certs: Option<&CertSource>,
) -> io::Result<()> {
    // The hosts this connection is bound to, oldest first.
    let mut binds = Vec::new();
    loop {
        let mut length = [0_u8; 4];
        if stream.read_exact(&mut length).await.is_err() {
            return Ok(());
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_AGENT_MESSAGE_BYTES {
            return Ok(());
        }
        let mut message = vec![0_u8; length];
        stream.read_exact(&mut message).await?;
        let reply = match message[0] {
            SSH_AGENTC_REQUEST_IDENTITIES => identities(backend, certs).await,
            SSH_AGENTC_SIGN_REQUEST => sign(backend, certs, &message[1..], &binds).await,
            SSH_AGENTC_EXTENSION => extension(&message[1..], &mut binds),
            _ => None,
        }
        .unwrap_or_else(|| vec![SSH_AGENT_FAILURE]);
        stream
            .write_all(&(reply.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&reply).await?;
    }
}

fn put_string(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value);
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4 + length)?;
    *input = &input[4 + length..];
    Some(value)
}

fn report(error: &KeyLeaseError) {
    let message = match error {
        KeyLeaseError::ApprovalRequired { approval_id } => {
            format!("approval {approval_id} was not decided in time")
        }
        KeyLeaseError::VaultLocked { .. } => "the vault is locked; unlock KeyLease".into(),
        KeyLeaseError::Denied { reason } => format!("denied: {reason}"),
        other => serde_json::to_string(other).unwrap_or_else(|_| "request failed".into()),
    };
    eprintln!("keylease ssh-agent: {message}");
}

/// Records a `session-bind@openssh.com` binding for the daemon to verify.
/// Any other extension is unsupported.
fn extension(mut body: &[u8], binds: &mut Vec<SshSessionBind>) -> Option<Vec<u8>> {
    if take_string(&mut body)? != SESSION_BIND || binds.len() >= MAX_SESSION_BINDS {
        return None;
    }
    let host_key = take_string(&mut body)?;
    let session_id = take_string(&mut body)?;
    let signature = take_string(&mut body)?;
    let forwarding = match body {
        [flag] => *flag != 0,
        _ => return None,
    };
    binds.push(SshSessionBind {
        host_key_blob: STANDARD.encode(host_key),
        session_id: STANDARD.encode(session_id),
        signature_blob: STANDARD.encode(signature),
        forwarding,
    });
    Some(vec![SSH_AGENT_SUCCESS])
}

async fn identities(backend: &Backend, certs: Option<&CertSource>) -> Option<Vec<u8>> {
    let mut count = 0_u32;
    let mut entries = Vec::new();
    // The certificate first: a server that trusts the CA needs nothing else.
    if let Some(certs) = certs
        && let Some((blob, comment)) = certs.current(backend).await
    {
        put_string(&mut entries, &blob);
        put_string(&mut entries, comment.as_bytes());
        count += 1;
    }
    let value = backend
        .call(|auth| RpcRequest::SshIdentities { auth })
        .await
        .map_err(|error| report(&error));
    let identities = match &value {
        Ok(value) => value.as_array()?.as_slice(),
        Err(_) if count > 0 => &[],
        Err(_) => return None,
    };
    let mut reply = vec![SSH_AGENT_IDENTITIES_ANSWER];
    for identity in identities {
        let blob = STANDARD
            .decode(identity.get("public_key_blob")?.as_str()?)
            .ok()?;
        let comment = identity.get("comment")?.as_str()?;
        put_string(&mut entries, &blob);
        put_string(&mut entries, comment.as_bytes());
        count += 1;
    }
    reply.extend_from_slice(&count.to_be_bytes());
    reply.extend_from_slice(&entries);
    Some(reply)
}

async fn sign(
    backend: &Backend,
    certs: Option<&CertSource>,
    mut body: &[u8],
    binds: &[SshSessionBind],
) -> Option<Vec<u8>> {
    let key_blob = take_string(&mut body)?;
    let data = take_string(&mut body)?;
    let flags = u32::from_be_bytes(body.get(..4)?.try_into().ok()?);
    if let Some(certs) = certs
        && let Some(signature) = certs.sign(key_blob, data).await
    {
        let mut reply = vec![SSH_AGENT_SIGN_RESPONSE];
        put_string(&mut reply, &signature?);
        return Some(reply);
    }
    let key_blob = STANDARD.encode(key_blob);
    let data = STANDARD.encode(data);
    let value = backend
        .call(|auth| RpcRequest::SshSign {
            auth,
            public_key_blob: key_blob.clone(),
            data: data.clone(),
            flags,
            session_binds: binds.to_vec(),
        })
        .await
        .map_err(|error| report(&error))
        .ok()?;
    let signature = STANDARD
        .decode(value.get("signature_blob")?.as_str()?)
        .ok()?;
    let mut reply = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut reply, &signature);
    Some(reply)
}

/// `keylease ssh-agent`: serve until interrupted, printing the socket for
/// `eval "$(keylease ssh-agent)"`-style use.
pub(crate) async fn run_agent(
    cli: &Cli,
    daemon: &Path,
    socket: Option<PathBuf>,
    cert: CertArgs,
) -> Result<()> {
    let backend = Backend::for_cli(cli, daemon)?;
    let (listener, path, _directory) = bind(socket)?;
    println!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
        shell_quote(&path.to_string_lossy())
    );
    io::stdout().flush().map_err(|_| KeyLeaseError::Storage)?;
    eprintln!("keylease ssh-agent: listening on {}", path.display());
    tokio::select! {
        () = serve_with(listener, backend, cert) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    let _ = fs::remove_file(&path);
    Ok(())
}

/// `keylease ssh ARGS…`: run OpenSSH with a private, single-use agent.
pub(crate) async fn run_ssh(
    cli: &Cli,
    daemon: &Path,
    args: Vec<String>,
    cert: CertArgs,
) -> Result<()> {
    let backend = Backend::for_cli(cli, daemon)?;
    let (listener, path, _directory) = bind(None)?;
    let server = tokio::spawn(serve_with(listener, backend, cert));
    let status = tokio::process::Command::new("ssh")
        .arg("-o")
        .arg(format!("IdentityAgent={}", path.display()))
        .args(&args)
        .env("SSH_AUTH_SOCK", &path)
        .status()
        .await
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "cannot run ssh; is OpenSSH installed?".into(),
        })?;
    server.abort();
    drop(_directory);
    std::process::exit(status.code().unwrap_or(1));
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_round_trip_and_truncation_is_rejected() {
        let mut buffer = Vec::new();
        put_string(&mut buffer, b"key");
        put_string(&mut buffer, b"");
        let mut input = buffer.as_slice();
        assert_eq!(take_string(&mut input), Some(&b"key"[..]));
        assert_eq!(take_string(&mut input), Some(&b""[..]));
        assert_eq!(take_string(&mut input), None);
        let mut truncated = &[0, 0, 0, 9, 1, 2][..];
        assert_eq!(take_string(&mut truncated), None);
    }

    #[test]
    fn a_session_bind_is_recorded_and_other_extensions_fail() {
        let mut message = Vec::new();
        put_string(&mut message, SESSION_BIND);
        put_string(&mut message, b"host-key");
        put_string(&mut message, b"session");
        put_string(&mut message, b"signature");
        message.push(1);
        let mut binds = Vec::new();
        assert_eq!(
            extension(&message, &mut binds),
            Some(vec![SSH_AGENT_SUCCESS])
        );
        assert_eq!(binds.len(), 1);
        assert!(binds[0].forwarding);
        assert_eq!(binds[0].session_id, STANDARD.encode("session"));
        // Trailing bytes, another extension, or one binding too many fail.
        let mut long = message.clone();
        long.push(0);
        assert_eq!(extension(&long, &mut binds), None);
        let mut other = Vec::new();
        put_string(&mut other, b"query");
        assert_eq!(extension(&other, &mut binds), None);
        while binds.len() < MAX_SESSION_BINDS {
            extension(&message, &mut binds).unwrap();
        }
        assert_eq!(extension(&message, &mut binds), None);
    }

    #[test]
    fn shell_quoting_survives_quotes() {
        assert_eq!(shell_quote("/tmp/a'b"), "'/tmp/a'\\''b'");
    }
}
