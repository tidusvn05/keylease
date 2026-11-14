//! Owner commands for SSH: create a certificate authority in the vault, and
//! pin an SSH key to the hosts it may sign logins for.
//!
//! Both run as the owner (master password), like `keylease add`: the CA
//! private key is generated here and goes straight into the vault, and pins
//! are a restriction only the owner sets.

use super::*;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, rand_core::OsRng};

#[derive(Subcommand)]
pub(crate) enum SshCaCommand {
    /// Generate an Ed25519 CA whose private key never leaves the vault, and
    /// print the public key for the servers' `TrustedUserCAKeys`.
    Init(InitArgs),
}

#[derive(Args)]
pub(crate) struct InitArgs {
    /// The item's title.
    title: String,
    /// A login name certificates may be issued for; repeatable.
    #[arg(long = "principal", required = true)]
    principals: Vec<String>,
    /// The vault project; default: the one `.keylease.json` names here.
    #[arg(long)]
    project: Option<String>,
    /// The group to file it in, created if missing; default: the project's slug.
    #[arg(long)]
    group: Option<String>,
}

#[derive(Args)]
pub(crate) struct PinArgs {
    /// The SSH key item.
    item_id: String,
    /// `HOST`, `HOST:PORT` (its keys are fetched with `ssh-keyscan`; compare
    /// the printed fingerprints with the server's) or a `SHA256:…` fingerprint.
    #[arg(required_unless_present = "clear")]
    hosts: Vec<String>,
    /// Replace the existing pins instead of adding to them.
    #[arg(long)]
    replace: bool,
    /// Remove every pin: the key signs for any host again.
    #[arg(long, conflicts_with_all = ["hosts", "replace"])]
    clear: bool,
}

fn text_field(key: &str, label: &str, value: String) -> ItemField {
    ItemField {
        id: FieldId::new(),
        key: key.into(),
        label: label.into(),
        value: FieldValue::Text(value),
        sensitivity: Sensitivity::PrivateMetadata,
        protected: false,
        semantic_role: None,
    }
}

fn valid_principal(principal: &str) -> bool {
    !principal.is_empty()
        && principal.len() <= 64
        && principal
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-@".contains(character))
}

/// `keylease ssh-ca init`.
pub(crate) fn init(db: &Path, args: InitArgs) -> Result<()> {
    if let Some(principal) = args.principals.iter().find(|p| !valid_principal(p)) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("`{principal}` is not a login name"),
        });
    }
    let project = match args.project {
        Some(project) => Some(project),
        None => std::env::current_dir()
            .ok()
            .and_then(|cwd| project::find_project_file(&cwd))
            .map(|(_, file)| file.project),
    };
    let service = admin_service(db)?;
    let owner = service.admin_owner()?;
    if let Some(project) = &project {
        service.ensure_project_admin(project)?;
    }
    let group_name = args
        .group
        .or_else(|| project.clone())
        .unwrap_or_else(|| "Default".into());
    let group = match service
        .list_groups()?
        .into_iter()
        .find(|group| group.name == group_name)
    {
        Some(group) => group,
        None => service.create_group(&group_name, None)?,
    };
    let key =
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| KeyLeaseError::Crypto)?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| KeyLeaseError::Crypto)?;
    let public_key = format!(
        "{} {}",
        key.public_key()
            .to_openssh()
            .map_err(|_| KeyLeaseError::Crypto)?,
        args.title
    );
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let item = service.create_entry(
        &owner,
        NewEntryInput {
            favorite: false,
            group_id: group.id,
            kind: "core.ssh_key".into(),
            title: args.title,
            project_slug: project.clone(),
            username: None,
            password: None,
            url: None,
            notes: None,
            custom_fields: vec![
                ItemField {
                    id: FieldId::new(),
                    key: "private_key".into(),
                    label: "Private key".into(),
                    value: FieldValue::Concealed(pem.to_string()),
                    sensitivity: Sensitivity::HighlySensitive,
                    protected: true,
                    semantic_role: Some("private_key".into()),
                },
                text_field("public_key", "Public key", public_key.clone()),
                text_field("fingerprint", "Fingerprint", fingerprint.clone()),
                text_field("key_type", "Key type", "ssh-ed25519".into()),
                text_field("ca_principals", "CA principals", args.principals.join(", ")),
            ],
            sections: vec![],
            totp: None,
            totp_uri: None,
            environment: None,
            personal: false,
        },
        &format!("ssh-ca-{}", RequestId::new().0),
        false,
    )?;
    print_json(&json!({
        "id": item.id,
        "title": item.title,
        "project": project,
        "fingerprint": fingerprint,
        "public_key": public_key,
        "principals": args.principals,
        "server_setup": [
            "Save public_key as /etc/ssh/keylease_ca.pub on each server",
            "Add `TrustedUserCAKeys /etc/ssh/keylease_ca.pub` to /etc/ssh/sshd_config",
            "Reload sshd (`sudo systemctl reload ssh`)",
        ],
        "use": format!("keylease ssh --cert {} USER@HOST", item.id.0),
    }))
}

/// Fingerprints of a host's keys from `ssh-keyscan`, as pin lines.
fn scan(target: &str) -> Result<Vec<String>> {
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => {
            (host, Some(port))
        }
        _ => (target, None),
    };
    if host.is_empty() || host.starts_with('-') {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("`{target}` is not a host"),
        });
    }
    let mut command = std::process::Command::new("ssh-keyscan");
    command.args(["-T", "10"]);
    if let Some(port) = port {
        command.args(["-p", port]);
    }
    let output = command
        .arg("--")
        .arg(host)
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: "cannot run ssh-keyscan; is OpenSSH installed?".into(),
        })?;
    let mut pins = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let [_, algorithm, key, ..] = tokens.as_slice()
            && let Ok(key) = PublicKey::from_openssh(&format!("{algorithm} {key}"))
        {
            let pin = format!("{} {target} {algorithm}", key.fingerprint(HashAlg::Sha256));
            if !pins.contains(&pin) {
                pins.push(pin);
            }
        }
    }
    if pins.is_empty() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!("ssh-keyscan found no host key for `{target}`"),
        });
    }
    Ok(pins)
}

/// `keylease ssh-pin`: set the `host_keys` field the service checks before
/// signing a login with the key.
pub(crate) fn pin(db: &Path, args: PinArgs) -> Result<()> {
    let mut added = Vec::new();
    for host in &args.hosts {
        if host.starts_with("SHA256:") {
            added.push(host.clone());
        } else {
            added.extend(scan(host)?);
        }
    }
    let service = admin_service(db)?;
    let owner = service.admin_owner()?;
    let id = ItemId(args.item_id);
    let view = service.get_entry_view(&owner, &id)?;
    if view.metadata.kind != "core.ssh_key" {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "only an SSH key item can be pinned to hosts".into(),
        });
    }
    let existing = view.fields.iter().find(|field| field.key == "host_keys");
    let mut lines: Vec<String> = match (
        existing.and_then(|field| field.value.as_ref()),
        args.replace || args.clear,
    ) {
        (Some(FieldValue::Text(text)), false) => text
            .lines()
            .map(str::to_owned)
            .filter(|line| !line.trim().is_empty())
            .collect(),
        _ => vec![],
    };
    for pin in &added {
        if !lines.contains(pin) {
            lines.push(pin.clone());
        }
    }
    let mut field = text_field("host_keys", "Host keys", lines.join("\n"));
    if let Some(existing) = existing {
        field.id = existing.id.clone();
    }
    service.update_entry(
        &owner,
        &id,
        keylease_service::EntryPatch {
            field_updates: vec![field],
            ..Default::default()
        },
        view.metadata.revision,
        &format!("ssh-pin-{}", RequestId::new().0),
        false,
    )?;
    print_json(&json!({
        "id": id,
        "host_keys": lines,
        "note": if lines.is_empty() {
            "no pins: the key signs logins to any host (each still needs approval or a trust)"
        } else {
            "the key now signs only logins to these host keys, from OpenSSH 8.9 or later"
        },
    }))
}
