//! Where brokers send their vault requests.
//!
//! The SSH agent, the PostgreSQL proxy and the MCP tools ask the same few
//! questions ("which keys", "sign this", "answer this SCRAM challenge"). From
//! the CLI and `keylease mcp` they go to the daemon over its Unix socket with
//! the agent's client token; from the HTTP gateway they go to the service in
//! this process as the agent its OAuth token names. Either way the request is
//! an ordinary `RpcRequest` and passes the same policy.

use super::*;
use keylease_rpc::{RpcCapabilities, handle_rpc_as};

#[derive(Clone)]
enum Target {
    Socket(PathBuf),
    InProcess(Arc<KeyLeaseService>, ActorContext),
}

#[derive(Clone)]
pub(crate) struct Backend {
    target: Target,
    auth: RpcAuth,
    /// How long a request that needs approval is retried before giving up.
    wait: std::time::Duration,
    /// Print a note on stderr while waiting (interactive CLI use).
    announce: bool,
    /// The approval this backend last gave up waiting for, for callers that
    /// only see a failed subprocess (an MCP tool running `ssh`).
    pending: Arc<std::sync::Mutex<Option<String>>>,
}

impl Backend {
    pub(crate) fn socket(daemon: &Path, auth: RpcAuth, wait: std::time::Duration) -> Self {
        Self {
            target: Target::Socket(daemon.to_path_buf()),
            auth,
            wait,
            announce: false,
            pending: Arc::default(),
        }
    }

    /// The CLI's backend: its credential, `--wait-approval`, a stderr note.
    pub(crate) fn for_cli(cli: &Cli, daemon: &Path) -> Result<Self> {
        let wait = std::time::Duration::from_secs(*APPROVAL_WAIT_SECONDS.get().unwrap_or(&0));
        Ok(Self {
            announce: true,
            ..Self::socket(daemon, auth(cli)?, wait)
        })
    }

    /// Requests as `actor`, which the caller has already authenticated.
    pub(crate) fn in_process(
        service: Arc<KeyLeaseService>,
        actor: ActorContext,
        wait: std::time::Duration,
    ) -> Self {
        let auth = RpcAuth {
            agent_id: actor.agent_id.clone(),
            token: SecretValue(String::new()),
            session_id: actor.client_session_id.clone(),
            purpose: actor.purpose.clone(),
        };
        Self {
            target: Target::InProcess(service, actor),
            auth,
            wait,
            announce: false,
            pending: Arc::default(),
        }
    }

    /// The same backend with another stated purpose for its approvals.
    pub(crate) fn with_purpose(&self, purpose: Option<String>) -> Self {
        let mut next = self.clone();
        next.auth.purpose = purpose.clone();
        if let Target::InProcess(_, actor) = &mut next.target {
            actor.purpose = purpose;
        }
        next.pending = Arc::default();
        next
    }

    /// Sends one request, waiting for an approval up to the backend's limit.
    pub(crate) async fn call(&self, build: impl Fn(RpcAuth) -> RpcRequest) -> Result<Value> {
        let started = std::time::Instant::now();
        let mut announced = false;
        loop {
            let outcome = match &self.target {
                Target::Socket(daemon) => {
                    let encoded = Zeroizing::new(
                        serde_json::to_vec(&build(self.auth.clone()))
                            .map_err(|_| KeyLeaseError::Storage)?,
                    );
                    rpc_once(daemon, &encoded).await
                }
                Target::InProcess(service, actor) => {
                    handle_rpc_as(
                        service,
                        RpcCapabilities::MOBILE,
                        actor.clone(),
                        build(self.auth.clone()),
                    )
                    .await
                }
            };
            match outcome {
                Err(KeyLeaseError::ApprovalRequired { approval_id })
                    if started.elapsed() < self.wait =>
                {
                    if self.announce && !announced {
                        eprintln!(
                            "KeyLease: approval {approval_id} is pending; approve it in KeyLease \
                             (waiting up to {}s)",
                            self.wait.as_secs()
                        );
                        announced = true;
                    }
                    tokio::time::sleep(APPROVAL_POLL_INTERVAL).await;
                }
                Err(KeyLeaseError::ApprovalRequired { approval_id }) => {
                    if let Ok(mut pending) = self.pending.lock() {
                        *pending = Some(approval_id.clone());
                    }
                    return Err(KeyLeaseError::ApprovalRequired { approval_id });
                }
                other => return other,
            }
        }
    }

    /// The approval the last timed-out request was waiting for, if any.
    pub(crate) fn take_pending(&self) -> Option<String> {
        self.pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }
}

/// The uid that owns a socket we bound: only peers with this uid may use it.
pub(crate) fn listener_owner_uid(listener: &UnixListener) -> u32 {
    listener
        .local_addr()
        .ok()
        .and_then(|address| address.as_pathname().map(Path::to_path_buf))
        .and_then(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX)
}
