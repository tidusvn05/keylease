//! `keylease ci run`: a CI/CD job reads a Managed project environment with its
//! platform's OIDC token (machine identity, v2 plan step 15) and runs a
//! command with the secrets in its environment, scrubbed from the output.
//! Nothing long-lived is stored in the pipeline, and no vault is needed.

use super::*;
use std::collections::BTreeMap;

#[derive(clap::Args)]
pub(crate) struct CiRunArgs {
    /// The server's API URL (e.g. https://vault.example.com/api).
    #[arg(long, env = "KEYLEASE_SERVER_URL")]
    server: String,
    /// The machine identity (mid_…) a project admin created.
    #[arg(long, env = "KEYLEASE_MACHINE_IDENTITY")]
    identity: String,
    /// Audience to request from GitHub Actions (must match the identity).
    #[arg(long, default_value = "keylease")]
    audience: String,
    /// A file holding the OIDC token (a Kubernetes projected token, …).
    /// Without it: $KEYLEASE_OIDC_TOKEN, then GitHub Actions' token service.
    #[arg(long)]
    oidc_token_file: Option<PathBuf>,
    #[arg(allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("keylease/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| KeyLeaseError::Storage)
}

async fn json_or_error(response: reqwest::Response, what: &str) -> Result<Value> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let reason = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|body| body["reason"].as_str().map(str::to_owned))
            .unwrap_or_else(|| status.to_string());
        return Err(KeyLeaseError::Denied {
            reason: format!("{what}: {reason}"),
        });
    }
    serde_json::from_str(&text).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: format!("{what}: unexpected answer"),
    })
}

/// The job's OIDC token: a file, $KEYLEASE_OIDC_TOKEN (GitLab `id_tokens`),
/// or GitHub Actions' token service (needs `permissions: id-token: write`).
async fn oidc_token(args: &CiRunArgs) -> Result<Zeroizing<String>> {
    if let Some(path) = &args.oidc_token_file {
        let token = fs::read_to_string(path).map_err(|_| KeyLeaseError::NotFound {
            resource: path.display().to_string(),
        })?;
        return Ok(Zeroizing::new(token.trim().to_owned()));
    }
    if let Ok(token) = std::env::var("KEYLEASE_OIDC_TOKEN")
        && !token.trim().is_empty()
    {
        return Ok(Zeroizing::new(token.trim().to_owned()));
    }
    let (Ok(url), Ok(bearer)) = (
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL"),
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) else {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "no OIDC token: pass --oidc-token-file, set KEYLEASE_OIDC_TOKEN, or run in \
                     GitHub Actions with `permissions: id-token: write`"
                .into(),
        });
    };
    let mut request_url = reqwest::Url::parse(&url).map_err(|_| KeyLeaseError::Storage)?;
    request_url
        .query_pairs_mut()
        .append_pair("audience", &args.audience);
    let response = client()?
        .get(request_url)
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    let body = json_or_error(response, "GitHub Actions OIDC token").await?;
    body["value"]
        .as_str()
        .map(|token| Zeroizing::new(token.to_owned()))
        .ok_or(KeyLeaseError::Storage)
}

pub(crate) async fn run(args: CiRunArgs) -> Result<()> {
    let program = args
        .command
        .first()
        .cloned()
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "no command to run".into(),
        })?;
    let base = args.server.trim_end_matches('/').to_owned();
    let token = oidc_token(&args).await?;
    let http = client()?;
    let granted = json_or_error(
        http.post(format!("{base}/v1/machine/token"))
            .json(&json!({"identity_id": args.identity, "token": token.as_str()}))
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?,
        "machine token",
    )
    .await?;
    drop(token);
    let access = Zeroizing::new(
        granted["access_token"]
            .as_str()
            .ok_or(KeyLeaseError::Storage)?
            .to_owned(),
    );
    let read = json_or_error(
        http.get(format!("{base}/v1/machine/secrets"))
            .bearer_auth(access.as_str())
            .send()
            .await
            .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?,
        "secrets",
    )
    .await?;
    let secrets: BTreeMap<String, String> =
        serde_json::from_value(read["secrets"].clone()).map_err(|_| KeyLeaseError::Storage)?;
    eprintln!(
        "KeyLease: {} secrets from {}/{}",
        secrets.len(),
        read["project"].as_str().unwrap_or_default(),
        read["environment"].as_str().unwrap_or_default()
    );
    let values: Vec<Zeroizing<String>> = secrets
        .values()
        .map(|value| Zeroizing::new(value.clone()))
        .collect();
    let patterns = std::sync::Arc::new(run::redaction_patterns(&values));
    let mut child = tokio::process::Command::new(&program);
    child
        .args(&args.command[1..])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (name, value) in &secrets {
        child.env(name, value);
    }
    let mut child = child.spawn().map_err(|_| KeyLeaseError::InvalidRequest {
        reason: format!("cannot run {program}"),
    })?;
    drop(secrets);
    drop(values);
    let stdout = child.stdout.take().ok_or(KeyLeaseError::Storage)?;
    let stderr = child.stderr.take().ok_or(KeyLeaseError::Storage)?;
    let out = tokio::spawn(run::pump(stdout, io::stdout(), patterns.clone()));
    let err = tokio::spawn(run::pump(stderr, io::stderr(), patterns));
    let status = child.wait().await.map_err(|_| KeyLeaseError::Storage)?;
    let _ = out.await;
    let _ = err.await;
    std::process::exit(status.code().unwrap_or(1));
}
