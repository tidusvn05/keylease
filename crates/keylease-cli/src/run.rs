//! `keylease run`: start a program with vault values in its environment
//! (ADR 0005, tier T3) and scrub them from what it prints.
//!
//! The values pass through this process and the child. Scrubbing keeps them out
//! of an agent's transcript by accident; it does not stop a program that
//! deliberately encodes a value, so injection is approved once per run.

use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use keylease_service::InjectRequest;
use tokio::io::AsyncRead;

/// Parses `NAME=kl://<vault>/<item>/<field>` (or `NAME=<item>/<field>`).
pub(crate) fn parse_binding(binding: &str) -> Result<(String, InjectRequest)> {
    let invalid = || KeyLeaseError::InvalidRequest {
        reason: "use --env NAME=kl://VAULT/ITEM/FIELD or NAME=ITEM/FIELD".into(),
    };
    let (name, reference) = binding.split_once('=').ok_or_else(invalid)?;
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(invalid());
    }
    let path = reference.strip_prefix("kl://").unwrap_or(reference);
    let parts: Vec<&str> = path.split('/').collect();
    let (item, field) = match parts.as_slice() {
        [vault, item, field] if vault.starts_with("vault_") => (*item, *field),
        [item, field] => (*item, *field),
        _ => return Err(invalid()),
    };
    if !item.starts_with("item_") || field.is_empty() {
        return Err(invalid());
    }
    Ok((
        name.to_owned(),
        InjectRequest {
            item_id: ItemId(item.into()),
            field: field.into(),
        },
    ))
}

pub(crate) fn shell_words(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            if !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+%".contains(c))
            {
                word.clone()
            } else {
                format!("'{}'", word.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the approver of a run sees: the whole command line first, then why.
/// Refused rather than cut when too long, so the command is never hidden.
pub(crate) fn run_purpose(argv: &[String], purpose: Option<&str>) -> Result<String> {
    let purpose = purpose.map(str::trim).filter(|purpose| !purpose.is_empty());
    let text = match purpose {
        Some(purpose) => format!("runs: {} — {purpose}", shell_words(argv)),
        None => format!("runs: {}", shell_words(argv)),
    };
    if text.chars().count() > MAX_PURPOSE_CHARS {
        return Err(KeyLeaseError::InvalidRequest {
            reason: format!(
                "the command line and purpose must fit in {MAX_PURPOSE_CHARS} characters so the \
                 approver sees all of it"
            ),
        });
    }
    Ok(text)
}

/// Every form of a secret worth scrubbing: raw, base64 and percent-encoded.
pub(crate) fn redaction_patterns(values: &[Zeroizing<String>]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut patterns = Vec::new();
    for value in values {
        if value.len() < 4 {
            // Too short to scrub without mangling ordinary output.
            continue;
        }
        let raw = value.as_bytes().to_vec();
        let encoded = STANDARD.encode(value.as_bytes()).into_bytes();
        let percent: Vec<u8> = value
            .bytes()
            .flat_map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => vec![byte],
                _ => format!("%{byte:02X}").into_bytes(),
            })
            .collect();
        for pattern in [raw, encoded, percent] {
            if !patterns
                .iter()
                .any(|known: &Zeroizing<Vec<u8>>| **known == pattern)
            {
                patterns.push(Zeroizing::new(pattern));
            }
        }
    }
    patterns.sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
    patterns
}

const REDACTED: &[u8] = b"[REDACTED by keylease]";

/// Scrubs `buffer`. Unless `at_end`, stops before a tail that could still
/// grow into a match and returns how many input bytes were consumed.
fn scrub_prefix(
    buffer: &[u8],
    patterns: &[Zeroizing<Vec<u8>>],
    at_end: bool,
    out: &mut Vec<u8>,
) -> usize {
    let mut index = 0;
    'outer: while index < buffer.len() {
        let rest = &buffer[index..];
        for pattern in patterns {
            if rest.starts_with(pattern) {
                out.extend_from_slice(REDACTED);
                index += pattern.len();
                continue 'outer;
            }
        }
        if !at_end && patterns.iter().any(|pattern| pattern.starts_with(rest)) {
            break;
        }
        out.push(buffer[index]);
        index += 1;
    }
    index
}

pub(crate) fn scrub(buffer: &[u8], patterns: &[Zeroizing<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buffer.len());
    scrub_prefix(buffer, patterns, true, &mut out);
    out
}

/// Copies a child stream to `sink`, scrubbing matches that span reads.
async fn pump<R: AsyncRead + Unpin, W: std::io::Write>(
    mut source: R,
    mut sink: W,
    patterns: std::sync::Arc<Vec<Zeroizing<Vec<u8>>>>,
) {
    let mut pending = Zeroizing::new(Vec::new());
    let mut chunk = [0_u8; 8192];
    loop {
        let read = source.read(&mut chunk).await.unwrap_or(0);
        let at_end = read == 0;
        pending.extend_from_slice(&chunk[..read]);
        let mut out = Vec::new();
        let consumed = scrub_prefix(&pending, &patterns, at_end, &mut out);
        pending.drain(..consumed);
        let _ = sink.write_all(&out);
        let _ = sink.flush();
        if at_end {
            return;
        }
    }
}

pub(crate) async fn run(
    cli: &Cli,
    daemon: &Path,
    bindings: Vec<String>,
    command: Vec<String>,
) -> Result<()> {
    let (names, requests): (Vec<String>, Vec<InjectRequest>) = bindings
        .iter()
        .map(|binding| parse_binding(binding))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .unzip();
    let program = command
        .first()
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "no command to run".into(),
        })?;
    let mut auth = auth(cli)?;
    auth.purpose = Some(run_purpose(&command, auth.purpose.as_deref())?);
    let value = rpc(
        daemon,
        RpcRequest::EntriesInject {
            auth,
            program: program.clone(),
            fields: requests,
            argv: command.clone(),
        },
    )
    .await?;
    let values: Vec<Zeroizing<String>> = serde_json::from_value::<Vec<String>>(value)
        .map_err(|_| KeyLeaseError::Storage)?
        .into_iter()
        .map(Zeroizing::new)
        .collect();
    if values.len() != names.len() {
        return Err(KeyLeaseError::Storage);
    }
    let patterns = std::sync::Arc::new(redaction_patterns(&values));
    let mut child = tokio::process::Command::new(program);
    child
        .args(&command[1..])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (name, value) in names.iter().zip(&values) {
        child.env(name, value.as_str());
    }
    let mut child = child.spawn().map_err(|_| KeyLeaseError::InvalidRequest {
        reason: format!("cannot run {program}"),
    })?;
    drop(values);
    let stdout = child.stdout.take().ok_or(KeyLeaseError::Storage)?;
    let stderr = child.stderr.take().ok_or(KeyLeaseError::Storage)?;
    let out = tokio::spawn(pump(stdout, io::stdout(), patterns.clone()));
    let err = tokio::spawn(pump(stderr, io::stderr(), patterns));
    let status = child.wait().await.map_err(|_| KeyLeaseError::Storage)?;
    let _ = out.await;
    let _ = err.await;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_parse_both_reference_forms() {
        let (name, request) = parse_binding("API_KEY=kl://vault_1/item_2/password").unwrap();
        assert_eq!(name, "API_KEY");
        assert_eq!(request.item_id.0, "item_2");
        assert_eq!(request.field, "password");
        assert!(parse_binding("TOKEN=item_3/token").is_ok());
        for bad in [
            "=item_1/x",
            "1X=item_1/x",
            "A-B=item_1/x",
            "A=item_1",
            "A=vault_1/x/y",
        ] {
            assert!(parse_binding(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scrubbing_covers_encodings() {
        let patterns = redaction_patterns(&[Zeroizing::new("s3cr3t/v@lue".into())]);
        let output = format!(
            "raw s3cr3t/v@lue b64 {} url {}",
            STANDARD.encode("s3cr3t/v@lue"),
            "s3cr3t%2Fv%40lue"
        );
        let scrubbed = String::from_utf8(scrub(output.as_bytes(), &patterns)).unwrap();
        assert!(!scrubbed.contains("s3cr3t"));
        assert_eq!(scrubbed.matches("[REDACTED by keylease]").count(), 3);
    }

    #[tokio::test]
    async fn scrubbing_survives_chunk_boundaries() {
        let patterns = std::sync::Arc::new(redaction_patterns(&[Zeroizing::new(
            "boundary-secret".into(),
        )]));
        let (mut writer, reader) = tokio::io::duplex(4);
        let task = tokio::spawn(async move {
            let mut sink = Vec::new();
            pump(reader, &mut sink, patterns).await;
            sink
        });
        writer.write_all(b"before boundary-").await.unwrap();
        writer.write_all(b"secret after").await.unwrap();
        drop(writer);
        let output = String::from_utf8(task.await.unwrap()).unwrap();
        assert_eq!(output, "before [REDACTED by keylease] after");
    }
}
