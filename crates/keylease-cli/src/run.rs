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

/// Parses `NAME=kl://<vault>/<item>/<field>` (or `NAME=<item>/<field>`), or
/// a named reference `NAME=kl://<project>[/<environment>]/<item>#<field>`.
pub(crate) fn parse_binding(binding: &str) -> Result<(String, InjectRequest)> {
    let invalid = || KeyLeaseError::InvalidRequest {
        reason: "use --env NAME=kl://PROJECT[/ENV]/ITEM#FIELD, NAME=kl://VAULT/ITEM/FIELD or \
                 NAME=ITEM/FIELD"
            .into(),
    };
    let (name, reference) = binding.split_once('=').ok_or_else(invalid)?;
    if !valid_env_name(name) {
        return Err(invalid());
    }
    let path = reference.strip_prefix("kl://").unwrap_or(reference);
    if let Some((item_path, field)) = path.split_once('#') {
        if field.is_empty()
            || item_path.is_empty()
            || !(2..=3).contains(&item_path.split('/').count())
        {
            return Err(invalid());
        }
        return Ok((
            name.to_owned(),
            InjectRequest {
                item_id: ItemId(format!("ref:{item_path}")),
                field: field.into(),
            },
        ));
    }
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

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The `.env` variables of a project's env items: every variable of each
/// active `core.environment` item in the project (and environment, when
/// given), as `NAME` → inject request. Later items do not override earlier
/// ones; explicit `--env` bindings override all of them.
async fn project_bindings(
    cli: &Cli,
    daemon: &Path,
    project: &str,
    environment: Option<&str>,
) -> Result<Vec<(String, InjectRequest)>> {
    let found = rpc(
        daemon,
        RpcRequest::EntriesSearch {
            auth: auth(cli)?,
            query: String::new(),
            project_slug: Some(project.to_owned()),
            unassigned: false,
        },
    )
    .await?;
    let items: Vec<ItemMetadata> =
        serde_json::from_value(found).map_err(|_| KeyLeaseError::Storage)?;
    let mut bindings: Vec<(String, InjectRequest)> = Vec::new();
    for item in items.iter().filter(|item| {
        item.kind == "core.environment"
            && environment.is_none_or(|wanted| {
                item.environment
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case(wanted))
            })
    }) {
        let view = rpc(
            daemon,
            RpcRequest::EntriesView {
                auth: auth(cli)?,
                id: item.id.clone(),
            },
        )
        .await?;
        let view: EntryView = serde_json::from_value(view).map_err(|_| KeyLeaseError::Storage)?;
        for field in view
            .fields
            .iter()
            .filter(|field| field.semantic_role.as_deref() == Some("environment_variable"))
        {
            let name = field.key.strip_prefix("env.").unwrap_or(&field.label);
            if valid_env_name(name) && !bindings.iter().any(|(known, _)| known == name) {
                bindings.push((
                    name.to_owned(),
                    InjectRequest {
                        item_id: item.id.clone(),
                        field: field.key.clone(),
                    },
                ));
            }
        }
    }
    if bindings.is_empty() {
        return Err(KeyLeaseError::NotFound {
            resource: match environment {
                Some(environment) => {
                    format!("env items in project {project}, environment {environment}")
                }
                None => format!("env items in project {project}"),
            },
        });
    }
    Ok(bindings)
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

pub(crate) struct RunOptions {
    pub(crate) bindings: Vec<String>,
    pub(crate) http: Vec<String>,
    pub(crate) proxy: Vec<String>,
    pub(crate) project: Option<String>,
    pub(crate) environment: Option<String>,
}

pub(crate) async fn run(
    cli: &Cli,
    daemon: &Path,
    options: RunOptions,
    command: Vec<String>,
) -> Result<()> {
    let RunOptions {
        bindings,
        http,
        proxy,
        project,
        environment,
    } = options;
    let proxy_items: Vec<ItemId> = proxy
        .iter()
        .map(|reference| crate::http_proxy::item_reference(reference))
        .collect::<Result<_>>()?;
    let http = http
        .iter()
        .map(|binding| crate::http_proxy::parse_http_binding(binding))
        .collect::<Result<Vec<_>>>()?;
    let explicit = bindings
        .iter()
        .map(|binding| parse_binding(binding))
        .collect::<Result<Vec<_>>>()?;
    let mut all = match &project {
        Some(project) => project_bindings(cli, daemon, project, environment.as_deref()).await?,
        None => Vec::new(),
    };
    for (name, request) in explicit {
        all.retain(|(known, _)| known != &name);
        all.push((name, request));
    }
    let (names, requests): (Vec<String>, Vec<InjectRequest>) = all.into_iter().unzip();
    let program = command
        .first()
        .ok_or_else(|| KeyLeaseError::InvalidRequest {
            reason: "no command to run".into(),
        })?;
    let mut auth = auth(cli)?;
    let purpose = run_purpose(&command, auth.purpose.as_deref())?;
    auth.purpose = Some(purpose.clone());
    let values: Vec<Zeroizing<String>> = if requests.is_empty() {
        Vec::new()
    } else {
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
        serde_json::from_value::<Vec<String>>(value)
            .map_err(|_| KeyLeaseError::Storage)?
            .into_iter()
            .map(Zeroizing::new)
            .collect()
    };
    if values.len() != names.len() {
        return Err(KeyLeaseError::Storage);
    }
    // HTTP bindings: a loopback proxy in this process for the child's
    // lifetime; the credential stays in the daemon.
    let mut http_env = Vec::new();
    if !http.is_empty() {
        let backend = crate::backend::Backend::for_cli(cli, daemon)?.with_purpose(Some(purpose));
        let (http_names, items): (Vec<String>, Vec<ItemId>) = http.into_iter().unzip();
        let proxy = crate::http_proxy::LocalProxy::bind(
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            backend,
            items,
        )
        .await?;
        http_env = http_names
            .into_iter()
            .zip(proxy.base_urls().to_vec())
            .collect();
        tokio::spawn(async move {
            if let Err(error) = proxy.serve().await {
                eprintln!("KeyLease HTTP proxy stopped: {error:?}");
            }
        });
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
    for (name, url) in &http_env {
        child.env(name, url);
    }
    // Intercepting proxy: HTTPS_PROXY plus a CA made for this run.
    let mut proxy_guard = None;
    if !proxy_items.is_empty() {
        let backend = crate::backend::Backend::for_cli(cli, daemon)?
            .with_purpose(Some(run_purpose(&command, cli.purpose.as_deref())?));
        let mitm = crate::http_mitm::MitmProxy::bind(backend, proxy_items).await?;
        for (name, value) in mitm.environment()?.variables {
            child.env(name, value);
        }
        proxy_guard = Some(mitm.spawn());
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
    // `exit` skips destructors: stop the proxy and remove its CA files first.
    if let Some((task, directory)) = proxy_guard.take() {
        task.abort();
        drop(directory);
    }
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
        // Named references: kl://PROJECT[/ENV]/ITEM#FIELD.
        let (name, request) =
            parse_binding("STRIPE_KEY=kl://shop/production/Stripe#secret_key").unwrap();
        assert_eq!(name, "STRIPE_KEY");
        assert_eq!(request.item_id.0, "ref:shop/production/Stripe");
        assert_eq!(request.field, "secret_key");
        assert!(parse_binding("DB=kl://shop/postgres#password").is_ok());
        for bad in ["A=kl://shop#x", "A=kl://shop/item#", "A=kl://a/b/c/d#x"] {
            assert!(parse_binding(bad).is_err(), "{bad}");
        }
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
