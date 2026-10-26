//! An OpenSSH agent whose keys never leave the KeyLease service (ADR 0005).
//!
//! This process speaks the agent protocol to `ssh`, `git` and `ssh-keygen`
//! and forwards only two questions to the daemon: which public keys exist,
//! and "sign these bytes with that key". It never holds a private key, so an
//! agent CLI that can run `ssh` still cannot read one. Each signature is a
//! policy decision in the daemon and may wait for an approval.

use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::os::unix::fs::DirBuilderExt;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

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

/// Accepts agent connections until the listener is dropped.
pub(crate) async fn serve(listener: UnixListener, daemon: PathBuf, auth: RpcAuth) {
    let owner_uid = fs::metadata(&daemon)
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        if stream.peer_cred().map(|cred| cred.uid()).ok() != Some(owner_uid) {
            eprintln!("keylease ssh-agent: rejected a peer with an unexpected uid");
            continue;
        }
        let daemon = daemon.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let _ = connection(stream, &daemon, &auth).await;
        });
    }
}

async fn connection(mut stream: UnixStream, daemon: &Path, auth: &RpcAuth) -> io::Result<()> {
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
            SSH_AGENTC_REQUEST_IDENTITIES => identities(daemon, auth).await,
            SSH_AGENTC_SIGN_REQUEST => sign(daemon, auth, &message[1..]).await,
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

async fn identities(daemon: &Path, auth: &RpcAuth) -> Option<Vec<u8>> {
    let value = rpc(daemon, RpcRequest::SshIdentities { auth: auth.clone() })
        .await
        .map_err(|error| report(&error))
        .ok()?;
    let identities = value.as_array()?;
    let mut reply = vec![SSH_AGENT_IDENTITIES_ANSWER];
    let mut entries = Vec::new();
    for identity in identities {
        let blob = STANDARD
            .decode(identity.get("public_key_blob")?.as_str()?)
            .ok()?;
        let comment = identity.get("comment")?.as_str()?;
        put_string(&mut entries, &blob);
        put_string(&mut entries, comment.as_bytes());
    }
    reply.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    reply.extend_from_slice(&entries);
    Some(reply)
}

async fn sign(daemon: &Path, auth: &RpcAuth, mut body: &[u8]) -> Option<Vec<u8>> {
    let key_blob = take_string(&mut body)?;
    let data = take_string(&mut body)?;
    let flags = u32::from_be_bytes(body.get(..4)?.try_into().ok()?);
    let value = rpc(
        daemon,
        RpcRequest::SshSign {
            auth: auth.clone(),
            public_key_blob: STANDARD.encode(key_blob),
            data: STANDARD.encode(data),
            flags,
        },
    )
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
pub(crate) async fn run_agent(cli: &Cli, daemon: &Path, socket: Option<PathBuf>) -> Result<()> {
    let auth = auth(cli)?;
    let (listener, path, _directory) = bind(socket)?;
    println!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
        shell_quote(&path.to_string_lossy())
    );
    io::stdout().flush().map_err(|_| KeyLeaseError::Storage)?;
    eprintln!("keylease ssh-agent: listening on {}", path.display());
    tokio::select! {
        () = serve(listener, daemon.to_path_buf(), auth) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    let _ = fs::remove_file(&path);
    Ok(())
}

/// `keylease ssh ARGS…`: run OpenSSH with a private, single-use agent.
pub(crate) async fn run_ssh(cli: &Cli, daemon: &Path, args: Vec<String>) -> Result<()> {
    let auth = auth(cli)?;
    let (listener, path, _directory) = bind(None)?;
    let server = tokio::spawn(serve(listener, daemon.to_path_buf(), auth));
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
    fn shell_quoting_survives_quotes() {
        assert_eq!(shell_quote("/tmp/a'b"), "'/tmp/a'\\''b'");
    }
}
