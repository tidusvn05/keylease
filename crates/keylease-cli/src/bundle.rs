//! `keylease node init`, `keylease export` and `keylease import`: move items
//! between a Mac and a VPS (or any two nodes) by copy and paste, without a
//! server. The text is an age-encrypted, signed bundle.

use super::*;
use keylease_service::BundleSelection;
use std::io::BufRead;

#[derive(Subcommand)]
pub(crate) enum NodeCommand {
    /// Print this node's ID (the age recipient other nodes export to) and its
    /// signing-key fingerprint; created on first use (master password).
    Init,
}

#[derive(clap::Args)]
pub(crate) struct ExportArgs {
    /// The receiving node's ID (`age1…`, from `keylease node init` there).
    #[arg(long)]
    to: String,
    /// Export every item of this project (personal items excluded).
    #[arg(long, required_unless_present = "item_ids")]
    project: Option<String>,
    /// Export this item (repeatable; personal items allowed).
    #[arg(long = "item-id")]
    item_ids: Vec<String>,
    /// A name for this node, shown to the receiver.
    #[arg(long)]
    name: Option<String>,
    /// Write the bundle to a file instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args)]
pub(crate) struct ImportArgs {
    /// Bundle file, or `-` (default) to paste it on stdin.
    #[arg(default_value = "-")]
    path: PathBuf,
    /// Trust a sender seen for the first time: its fingerprint, compared with
    /// `keylease node init` on the sending node.
    #[arg(long)]
    trust_sender: Option<String>,
    /// Store independent, editable copies instead of read-only items that
    /// later bundles from the same sender update.
    #[arg(long)]
    editable: bool,
    /// Show what the bundle contains without storing it.
    #[arg(long)]
    preview: bool,
}

pub(crate) fn node_command(db: &Path, command: NodeCommand) -> Result<()> {
    let service = admin_service(db)?;
    match command {
        NodeCommand::Init => {
            let identity = service.node_identity()?;
            print_json(&json!({
                "node_id": identity.node_id,
                "fingerprint": identity.fingerprint,
                "signing_key": identity.signing_key,
                "next": "On the other node: keylease export --to NODE_ID --project P, then paste \
                         the output into `keylease import` here.",
            }))
        }
    }
}

pub(crate) fn export(db: &Path, args: ExportArgs) -> Result<()> {
    let service = admin_service(db)?;
    let armored = service.export_bundle(
        &args.to,
        &BundleSelection {
            project_slug: args.project,
            item_ids: args.item_ids.into_iter().map(ItemId).collect(),
        },
        args.name.as_deref(),
    )?;
    match args.out {
        Some(path) => {
            write_private_file(&path, armored.as_bytes())?;
            eprintln!(
                "Wrote {}. Copy it to the other node and run `keylease import FILE`.",
                path.display()
            );
            Ok(())
        }
        None => {
            println!("{armored}");
            Ok(())
        }
    }
}

pub(crate) fn import(db: &Path, args: ImportArgs) -> Result<()> {
    let armored = read_bundle(&args.path)?;
    let service = admin_service(db)?;
    if args.preview {
        return print_json(&service.preview_bundle(&armored)?);
    }
    let report = service.import_bundle(&armored, args.trust_sender.as_deref(), args.editable)?;
    print_json(&report)
}

/// Reads a bundle from a file, or from stdin until its END line (so a pasted
/// bundle needs no Ctrl-D).
fn read_bundle(path: &Path) -> Result<String> {
    let too_large = || KeyLeaseError::InvalidRequest {
        reason: "bundle is too large".into(),
    };
    if path != Path::new("-") {
        let text = fs::read_to_string(path).map_err(|_| KeyLeaseError::NotFound {
            resource: path.display().to_string(),
        })?;
        return if text.len() > 16 * 1024 * 1024 {
            Err(too_large())
        } else {
            Ok(text)
        };
    }
    if stdin_is_terminal() {
        eprintln!("Paste the bundle (from -----BEGIN to -----END):");
    }
    let mut text = String::new();
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|_| KeyLeaseError::Storage)?;
        text.push_str(&line);
        text.push('\n');
        if text.len() > 16 * 1024 * 1024 {
            return Err(too_large());
        }
        if line.trim() == "-----END AGE ENCRYPTED FILE-----" {
            break;
        }
    }
    Ok(text)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: format!("cannot create {} (it must not exist yet)", path.display()),
        })?;
    file.write_all(bytes).map_err(|_| KeyLeaseError::Storage)
}

/// Reads a plaintext secret file the user acknowledged.
pub(crate) fn read_plaintext_source(path: &Path, acknowledged: bool, what: &str) -> Result<String> {
    if !acknowledged {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!(
                "{what} files hold plaintext secrets; pass --acknowledge-plaintext, and delete the \
                 file after the import"
            ),
        });
    }
    let mut text = String::new();
    let mut file = fs::File::open(path).map_err(|_| KeyLeaseError::NotFound {
        resource: path.display().to_string(),
    })?;
    std::io::Read::by_ref(&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| KeyLeaseError::InvalidRequest {
            reason: format!("{} is not UTF-8 text", path.display()),
        })?;
    Ok(text)
}
