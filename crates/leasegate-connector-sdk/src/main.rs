use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::Utc;
use clap::{Parser, Subcommand};
use leasegate_connector_sdk::{
    CONNECTOR_PACKAGE_VERSION, ConnectorPackagePayload, ConnectorPackageSigner,
    action_input_schema, conformance_report, manifest_digest,
};
use leasegate_connectors::ConnectorManifest;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(
    name = "leasegate-connector",
    about = "Validate and package LeaseGate connectors"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate {
        manifest: PathBuf,
    },
    Inspect {
        manifest: PathBuf,
    },
    Schema {
        manifest: PathBuf,
        #[arg(long)]
        action: String,
    },
    Package {
        manifest: PathBuf,
        #[arg(long)]
        publisher_id: String,
        #[arg(long)]
        signing_key_file: PathBuf,
        #[arg(long)]
        artifact_digest_sha256: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate { manifest } => {
            let manifest = load_manifest(&manifest)?;
            let report = conformance_report(&manifest);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                bail!("connector manifest failed conformance");
            }
        }
        Command::Inspect { manifest } => {
            let manifest = load_manifest(&manifest)?;
            println!("provider: {}", manifest.provider);
            println!("version: {}", manifest.version);
            println!("actions: {}", manifest.actions.len());
            println!("manifest_sha256: {}", manifest_digest(&manifest)?);
        }
        Command::Schema { manifest, action } => {
            let manifest = load_manifest(&manifest)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&action_input_schema(&manifest, &action)?)?
            );
        }
        Command::Package {
            manifest,
            publisher_id,
            signing_key_file,
            artifact_digest_sha256,
        } => {
            let manifest = load_manifest(&manifest)?;
            validate_secret_file_permissions(&signing_key_file)?;
            let mut encoded = String::from_utf8(read_bounded(&signing_key_file, 4_096)?)
                .context("signing key file must contain UTF-8")?;
            let mut key = STANDARD_NO_PAD
                .decode(encoded.trim())
                .context("signing key file must contain unpadded base64")?;
            encoded.zeroize();
            let signer = ConnectorPackageSigner::from_bytes(publisher_id, &key)?;
            key.zeroize();
            let package = signer.sign(ConnectorPackagePayload {
                schema_version: CONNECTOR_PACKAGE_VERSION,
                manifest,
                artifact_digest_sha256,
                published_at: Utc::now(),
            })?;
            println!("{}", serde_json::to_string_pretty(&package)?);
        }
    }
    Ok(())
}

fn load_manifest(path: &Path) -> Result<ConnectorManifest> {
    let bytes = read_bounded(path, 1024 * 1024)?;
    serde_json::from_slice(&bytes).context("parse connector manifest")
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("read metadata for {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!(
            "{} must be a bounded non-empty regular file",
            path.display()
        );
    }
    std::fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn validate_secret_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("read metadata for {}", path.display()))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("signing key file must not be group/world accessible");
        }
    }
    Ok(())
}
