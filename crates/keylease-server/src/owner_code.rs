//! One-time setup codes: link the first vault as the owner without copying
//! the admin token off the server.
//!
//! `keylease-server setup` (or `keylease-server owner-code`) prints a short
//! code and stores only its SHA-256 and expiry in a file next to the other
//! secrets (`KEYLEASE_OWNER_CODES_FILE`). `keylease cloud init` sends it in
//! place of the admin token; the server accepts it once, for creating a
//! relay account only, and removes it. Nothing else takes a setup code.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// Codes look like `KLS-ABCD-EFGH-JKLM-NPQR` (80 random bits).
pub const PREFIX: &str = "KLS";
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

static FILE_LOCK: Mutex<()> = Mutex::new(());

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Upper case without separators, so a code typed in any form matches.
pub fn normalize(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Whether `presented` has the shape of a setup code (not an admin token).
pub fn looks_like_code(presented: &str) -> bool {
    let normalized = normalize(presented);
    normalized.len() == PREFIX.len() + 16 && normalized.starts_with(PREFIX)
}

fn digest(code: &str) -> String {
    Sha256::digest(normalize(code).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Makes a code valid for `minutes`, records it in `file` and returns it.
pub fn issue(file: &Path, minutes: u64) -> std::io::Result<String> {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let chars: Vec<char> = bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect();
    let groups: Vec<String> = chars.chunks(4).map(|c| c.iter().collect()).collect();
    let code = format!("{PREFIX}-{}", groups.join("-"));
    let _guard = FILE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let mut keep = live_lines(file);
    keep.push(format!("{} {}", digest(&code), now() + minutes * 60));
    write_private(file, &keep)?;
    Ok(code)
}

/// Accepts `presented` once if it is a live code in `file`.
pub fn consume(file: &Path, presented: &str) -> bool {
    let wanted = digest(presented);
    let _guard = FILE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let lines = live_lines(file);
    let found = lines
        .iter()
        .any(|line| line.split_whitespace().next() == Some(wanted.as_str()));
    if found {
        let rest: Vec<String> = lines
            .into_iter()
            .filter(|line| line.split_whitespace().next() != Some(wanted.as_str()))
            .collect();
        if write_private(file, &rest).is_err() {
            // A code that cannot be crossed out must not work twice.
            return false;
        }
    }
    found
}

/// Lines whose code has not expired.
fn live_lines(file: &Path) -> Vec<String> {
    let now = now();
    fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            let mut parts = line.split_whitespace();
            parts.next().is_some_and(|hash| hash.len() == 64)
                && parts
                    .next()
                    .and_then(|expiry| expiry.parse::<u64>().ok())
                    .is_some_and(|expiry| expiry > now)
        })
        .map(str::to_owned)
        .collect()
}

fn write_private(file: &Path, lines: &[String]) -> std::io::Result<()> {
    let temporary = file.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = options.open(&temporary)?;
    for line in lines {
        writeln!(out, "{line}")?;
    }
    out.sync_all()?;
    fs::rename(&temporary, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_works_once_in_any_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("owner_codes");
        let code = issue(&file, 30).unwrap();
        assert!(looks_like_code(&code));
        assert!(!looks_like_code(
            "kladmin_abcdefghijklmnopqrstuvwxyz0123456789"
        ));
        assert!(!consume(&file, "KLS-AAAA-AAAA-AAAA-AAAA"));
        let typed = code.to_lowercase().replace('-', " ");
        assert!(consume(&file, &typed));
        assert!(!consume(&file, &code), "once only");
    }

    #[test]
    fn an_expired_code_is_refused_and_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("owner_codes");
        let code = issue(&file, 0).unwrap();
        assert!(!consume(&file, &code));
        let other = issue(&file, 10).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap().lines().count(), 1);
        assert!(consume(&file, &other));
    }
}
