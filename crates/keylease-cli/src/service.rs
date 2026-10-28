//! `keylease service`: run the daemon as a systemd system service that unlocks itself at boot
//! from a host-sealed credential (docs/agent-approvals.md, "Unlocking after a reboot").
//!
//! keylease itself runs as the vault's owner; only the steps that need root (sealing the
//! credential, writing the unit, systemctl) go through `sudo`. The master password is checked
//! against the vault before it is sealed, and reaches `systemd-creds` on stdin only.

use super::*;
use std::process::{Command as Process, Stdio};

const CREDENTIAL_NAME: &str = "keylease-master-password";
const CREDSTORE: &str = "/etc/credstore.encrypted";
const UNIT_DIR: &str = "/etc/systemd/system";

#[derive(Subcommand)]
pub(crate) enum ServiceCommand {
    /// Install and start the systemd service: asks for the master password, then for sudo
    Install {
        /// Service name (one per vault)
        #[arg(long, default_value = "keylease")]
        name: String,
        /// Lock the vault after this long without activity (30m, 6h, 1d, 7d)
        #[arg(long, default_value = "1d", value_parser = cloud::parse_ttl)]
        idle_lock: Duration,
        /// Print the unit and the commands without changing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Show whether the service is enabled and running, and the vault state
    Status {
        #[arg(long, default_value = "keylease")]
        name: String,
    },
    /// Stop and remove the service and its sealed credential (the vault is kept)
    Uninstall {
        #[arg(long, default_value = "keylease")]
        name: String,
    },
}

struct Paths {
    unit: PathBuf,
    credential: PathBuf,
}

fn paths(name: &str) -> Result<Paths> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "a service name uses a-z, 0-9 and -".into(),
        });
    }
    Ok(Paths {
        unit: Path::new(UNIT_DIR).join(format!("{name}.service")),
        credential: Path::new(CREDSTORE).join(format!("{name}-master-password")),
    })
}

/// A path written into the unit as it is: systemd would interpret quotes, `%`, `$`, `\` and
/// whitespace.
fn unit_path(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or(KeyLeaseError::InvalidRequest {
        reason: "paths must be UTF-8".into(),
    })?;
    if !path.is_absolute()
        || text
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "\"'%$\\;".contains(c))
    {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!(
                "{text} cannot go into a systemd unit; use an absolute path without spaces, quotes, %, $ or \\"
            ),
        });
    }
    Ok(text.into())
}

fn render_unit(
    user: &str,
    exe: &Path,
    db: &Path,
    socket: &Path,
    credential: &Path,
    idle_lock: Duration,
) -> Result<String> {
    Ok(format!(
        "# Written by `keylease service install`; `keylease service uninstall` removes it.\n\
         [Unit]\n\
         Description=KeyLease vault {db}\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         User={user}\n\
         LoadCredentialEncrypted={CREDENTIAL_NAME}:{credential}\n\
         ExecStart={exe} --db {db} --socket {socket} serve --session-ttl-seconds {ttl}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=full\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        db = unit_path(db)?,
        exe = unit_path(exe)?,
        socket = unit_path(socket)?,
        credential = unit_path(credential)?,
        ttl = idle_lock.num_seconds(),
    ))
}

fn require_systemd() -> Result<()> {
    if cfg!(target_os = "linux") && Path::new("/run/systemd/system").is_dir() {
        Ok(())
    } else {
        Err(KeyLeaseError::InvalidRequest {
            reason: "`keylease service` needs Linux with systemd; elsewhere run `keylease serve`"
                .into(),
        })
    }
}

fn current_uid() -> Result<u32> {
    fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|_| KeyLeaseError::Storage)
}

fn current_user() -> Result<String> {
    let output = Process::new("id")
        .arg("-un")
        .output()
        .map_err(|_| KeyLeaseError::Storage)?;
    let user = String::from_utf8(output.stdout)
        .map_err(|_| KeyLeaseError::Storage)?
        .trim()
        .to_owned();
    if !output.status.success() || user.is_empty() {
        return Err(KeyLeaseError::Storage);
    }
    Ok(user)
}

/// Runs `sudo ARGS`, feeding `input` on stdin when given; sudo asks for its own password on
/// the terminal.
fn sudo(args: &[&str], input: Option<&[u8]>) -> Result<()> {
    let mut child = Process::new("sudo")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::null())
        .spawn()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "cannot run sudo".into(),
        })?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().ok_or(KeyLeaseError::Storage)?;
        stdin.write_all(input).map_err(|_| KeyLeaseError::Storage)?;
    }
    let status = child.wait().map_err(|_| KeyLeaseError::Storage)?;
    if status.success() {
        Ok(())
    } else {
        Err(KeyLeaseError::InvalidRequest {
            reason: format!("`sudo {}` failed", args.join(" ")),
        })
    }
}

fn systemctl_query(args: &[&str]) -> String {
    Process::new("systemctl")
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

async fn vault_status(socket: &Path) -> Option<Value> {
    rpc(socket, RpcRequest::Status).await.ok()
}

pub(crate) async fn service_command(
    db: &Path,
    socket: &Path,
    command: ServiceCommand,
) -> Result<()> {
    require_systemd()?;
    match command {
        ServiceCommand::Install {
            name,
            idle_lock,
            dry_run,
        } => install(db, socket, &name, idle_lock, dry_run).await,
        ServiceCommand::Status { name } => {
            let paths = paths(&name)?;
            let unit = format!("{name}.service");
            print_json(&json!({
                "service": unit,
                "installed": paths.unit.is_file(),
                "enabled": systemctl_query(&["is-enabled", &unit]),
                "active": systemctl_query(&["is-active", &unit]),
                "vault": vault_status(socket).await,
            }))
        }
        ServiceCommand::Uninstall { name } => {
            let paths = paths(&name)?;
            let unit = format!("{name}.service");
            sudo(&["-v"], None)?;
            sudo(&["systemctl", "disable", "--now", &unit], None)?;
            sudo(
                &[
                    "rm",
                    "-f",
                    &unit_path(&paths.unit)?,
                    &unit_path(&paths.credential)?,
                ],
                None,
            )?;
            sudo(&["systemctl", "daemon-reload"], None)?;
            print_json(&json!({"removed": unit, "vault_kept": db}))
        }
    }
}

async fn install(
    db: &Path,
    socket: &Path,
    name: &str,
    idle_lock: Duration,
    dry_run: bool,
) -> Result<()> {
    let paths = paths(name)?;
    let unit_name = format!("{name}.service");
    let db = fs::canonicalize(db).map_err(|_| KeyLeaseError::InvalidRequest {
        reason: format!(
            "no vault at {}; run `keylease vault init` first",
            db.display()
        ),
    })?;
    let uid = current_uid()?;
    if uid == 0 {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "run this as the user that owns the vault and runs the agents, not as root; \
                     it asks for sudo itself"
                .into(),
        });
    }
    if fs::metadata(&db).map_err(|_| KeyLeaseError::Storage)?.uid() != uid {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "the vault belongs to another user; the daemon accepts only the vault owner"
                .into(),
        });
    }
    let socket = if socket.is_absolute() {
        socket.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| KeyLeaseError::Storage)?
            .join(socket)
    };
    let exe = fs::canonicalize(std::env::current_exe().map_err(|_| KeyLeaseError::Storage)?)
        .map_err(|_| KeyLeaseError::Storage)?;
    let user = current_user()?;
    let unit = render_unit(&user, &exe, &db, &socket, &paths.credential, idle_lock)?;
    let running = systemctl_query(&["is-active", &unit_name]) == "active";
    if !running && vault_status(&socket).await.is_some() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!(
                "a keylease daemon already listens on {}; stop it first",
                socket.display()
            ),
        });
    }
    if dry_run {
        println!("# {}\n{unit}", paths.unit.display());
        println!(
            "# then, with sudo:\n\
             #   install -d -m 0700 {CREDSTORE}\n\
             #   systemd-creds encrypt --name={CREDENTIAL_NAME} - {}   (master password on stdin)\n\
             #   systemctl daemon-reload && systemctl enable {unit_name} && systemctl restart {unit_name}",
            paths.credential.display()
        );
        return Ok(());
    }

    let password = prompt("Master password: ")?;
    service(&db)?
        .unlock(password.trim().as_bytes(), Duration::minutes(1))
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "the master password does not open this vault".into(),
        })?;
    eprintln!("Master password checked. sudo may ask for your password next.");
    sudo(&["-v"], None)?;
    sudo(&["install", "-d", "-m", "0700", CREDSTORE], None)?;
    sudo(
        &[
            "systemd-creds",
            "encrypt",
            &format!("--name={CREDENTIAL_NAME}"),
            "-",
            &unit_path(&paths.credential)?,
        ],
        Some(password.trim().as_bytes()),
    )?;
    drop(password);
    sudo(&["tee", &unit_path(&paths.unit)?], Some(unit.as_bytes()))?;
    sudo(&["systemctl", "daemon-reload"], None)?;
    sudo(&["systemctl", "enable", &unit_name], None)?;
    sudo(&["systemctl", "restart", &unit_name], None)?;

    let mut status = None;
    for _ in 0..60 {
        if let Some(value) = vault_status(&socket).await {
            status = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let Some(status) = status else {
        let last = Process::new("journalctl")
            .args(["-u", &unit_name, "-n", "1", "-o", "cat", "--no-pager"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        if let Some(last) = last {
            eprintln!("{unit_name}: {last}");
        }
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("{unit_name} did not start; see `journalctl -u {unit_name}`"),
        });
    };
    print_json(&json!({
        "service": unit_name,
        "unit_file": paths.unit,
        "credential": paths.credential,
        "socket": socket,
        "locked": status.get("locked"),
        "idle_lock_seconds": idle_lock.num_seconds(),
        "next": "Register an agent: keylease client register NAME, then export KEYLEASE_AGENT_ID=agent_NAME. \
                 The vault locks after the idle time; `sudo systemctl restart` unlocks it again. \
                 Anyone who is root on this host, or runs as this user, can use the vault while it runs.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_runs_the_vault_owner_with_the_sealed_credential() {
        let paths = paths("keylease").unwrap();
        let unit = render_unit(
            "deployer",
            Path::new("/home/deployer/.cargo/bin/keylease"),
            Path::new("/home/deployer/.keylease/keylease.sqlite"),
            Path::new("/home/deployer/.keylease/run/keylease.sock"),
            &paths.credential,
            Duration::days(1),
        )
        .unwrap();
        assert!(unit.contains("\nUser=deployer\n"));
        assert!(unit.contains(
            "\nLoadCredentialEncrypted=keylease-master-password:/etc/credstore.encrypted/keylease-master-password\n"
        ));
        assert!(unit.contains(
            "\nExecStart=/home/deployer/.cargo/bin/keylease --db /home/deployer/.keylease/keylease.sqlite \
             --socket /home/deployer/.keylease/run/keylease.sock serve --session-ttl-seconds 86400\n"
        ));
        assert_eq!(
            paths.unit,
            Path::new("/etc/systemd/system/keylease.service")
        );
    }

    #[test]
    fn names_and_paths_systemd_would_interpret_are_refused() {
        assert!(paths("../etc").is_err());
        assert!(paths("Keylease").is_err());
        assert!(paths("work-2").is_ok());
        assert!(unit_path(Path::new("/home/a b/vault.sqlite")).is_err());
        assert!(unit_path(Path::new("/home/a/%h.sqlite")).is_err());
        assert!(unit_path(Path::new("relative.sqlite")).is_err());
        assert!(unit_path(Path::new("/home/a/.keylease/keylease.sqlite")).is_ok());
    }
}
