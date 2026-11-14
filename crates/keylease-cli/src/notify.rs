//! `keylease notify`: a push to the owner's phone when an agent waits for approval.
//!
//! The daemon posts to an ntfy topic (https://ntfy.sh or a self-hosted server) or
//! any URL that takes a plain-text POST. The message says only that requests are
//! waiting and on which host, never what they are: the push service and anyone who
//! learns the topic see no agent, item or purpose. The setting lives in
//! `notify.json` next to the vault and is read on every check, so changing it needs
//! no restart.

use super::*;
use std::collections::HashSet;

const FILE: &str = "notify.json";
/// How often the daemon looks for new requests.
const CHECK: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NotifyConfig {
    url: String,
}

#[derive(Subcommand)]
pub(crate) enum NotifyCommand {
    /// Send pushes to URL (an ntfy topic such as https://ntfy.sh/NAME). Without URL,
    /// a new private topic on ntfy.sh is made up for you.
    Set { url: Option<String> },
    /// Send a test push.
    Test,
    /// Show where pushes go.
    Status,
    /// Stop sending pushes.
    Off,
}

fn config_path(db: &Path) -> PathBuf {
    db.parent().unwrap_or_else(|| Path::new(".")).join(FILE)
}

fn load(db: &Path) -> Option<NotifyConfig> {
    let path = config_path(db);
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn validate_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: "not a URL".into(),
    })?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "use an https:// URL (http:// only to this host)".into(),
        });
    }
    Ok(())
}

/// The host's name, so pushes from several servers can be told apart.
fn host_name() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this host".into())
}

async fn post(url: &str, message: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .post(url)
        .header("Title", "KeyLease")
        .header("Tags", "key")
        .timeout(std::time::Duration::from_secs(10))
        .body(message.to_owned())
        .send()
        .await
        .map_err(|_| KeyLeaseError::ConnectorUnavailable { retryable: true })?;
    if !response.status().is_success() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("the push server answered {}", response.status()),
        });
    }
    Ok(())
}

pub(crate) async fn notify_command(db: &Path, command: NotifyCommand) -> Result<()> {
    let path = config_path(db);
    match command {
        NotifyCommand::Set { url } => {
            let generated = url.is_none();
            let url = match url {
                Some(url) => url,
                None => format!(
                    "https://ntfy.sh/keylease-{}",
                    RequestId::new()
                        .0
                        .trim_start_matches("req_")
                        .chars()
                        .filter(char::is_ascii_alphanumeric)
                        .take(24)
                        .collect::<String>()
                ),
            };
            validate_url(&url)?;
            let mut contents = serde_json::to_vec_pretty(&NotifyConfig { url: url.clone() })
                .map_err(|_| KeyLeaseError::Storage)?;
            contents.push(b'\n');
            // The topic name is what keeps others from reading or sending pushes.
            write_atomic(&path, &contents)?;
            post(
                &url,
                &format!("KeyLease pushes from {} are on", host_name()),
            )
            .await?;
            print_json(&json!({
                "url": url,
                "next": if generated {
                    "Subscribe to this topic in the ntfy app (Android, iOS or web); a test push \
                     was sent. Keep the URL private."
                } else {
                    "A test push was sent."
                },
            }))
        }
        NotifyCommand::Test => {
            let config = load(db).ok_or(KeyLeaseError::InvalidRequest {
                reason: "pushes are off; `keylease notify set` first".into(),
            })?;
            post(
                &config.url,
                &format!("Test push from KeyLease on {}", host_name()),
            )
            .await?;
            print_json(&json!({"sent": true, "url": config.url}))
        }
        NotifyCommand::Status => {
            print_json(&json!({"enabled": load(db).is_some(), "url": load(db).map(|c| c.url)}))
        }
        NotifyCommand::Off => {
            let removed = fs::remove_file(&path).is_ok();
            print_json(&json!({"enabled": false, "removed": removed}))
        }
    }
}

/// What a push says: only that requests wait, and where.
fn message(new: usize, pending: usize, host: &str) -> String {
    let what = if new == 1 {
        "An agent is".to_owned()
    } else {
        format!("{new} agent requests are")
    };
    let rest = if pending > new {
        format!(" ({pending} pending)")
    } else {
        String::new()
    };
    format!("{what} waiting for your approval on {host}{rest}. Open `keylease approve`.")
}

/// Watches for new pending approvals and pushes when `notify.json` is set.
pub(crate) fn spawn_notifier(service: Arc<KeyLeaseService>, db: PathBuf) {
    tokio::spawn(async move {
        let host = host_name();
        let mut seen = HashSet::new();
        let mut primed = false;
        loop {
            tokio::time::sleep(CHECK).await;
            let Some(config) = load(&db) else {
                continue;
            };
            // Locked: approvals cannot be listed (or decided) until it is unlocked.
            let Ok(pending) = service.list_pending_approvals_admin(1000) else {
                continue;
            };
            let ids: HashSet<String> = pending
                .iter()
                .map(|approval| approval.id.0.clone())
                .collect();
            let new = ids.difference(&seen).count();
            // Requests already waiting when pushes start were not missed by a push.
            if primed
                && new > 0
                && let Err(error) = post(&config.url, &message(new, ids.len(), &host)).await
            {
                eprintln!(
                    "KeyLease push failed: {}",
                    serde_json::to_string(&error).unwrap_or_default()
                );
            }
            primed = true;
            seen = ids;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pushes_say_that_requests_wait_and_nothing_else() {
        assert_eq!(
            message(1, 1, "vps1"),
            "An agent is waiting for your approval on vps1. Open `keylease approve`."
        );
        assert_eq!(
            message(2, 5, "vps1"),
            "2 agent requests are waiting for your approval on vps1 (5 pending). Open \
             `keylease approve`."
        );
    }

    #[test]
    fn push_urls_are_https_or_this_host() {
        assert!(validate_url("https://ntfy.sh/keylease-abc").is_ok());
        assert!(validate_url("http://127.0.0.1:8080/topic").is_ok());
        assert!(validate_url("http://ntfy.sh/topic").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }
}
