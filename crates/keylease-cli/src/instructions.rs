//! The KeyLease block in a project's agent instructions (`CLAUDE.md`,
//! `AGENTS.md`): how agents should find, use, add and change secrets.
//!
//! The block sits between markers, so keylease can find, update or remove its
//! own text without touching anything else in the file. It goes into one file:
//! when one of the two files imports the other (`@AGENTS.md`), the imported one.

use super::*;

const BEGIN: &str = "<!-- keylease:begin";
const END: &str = "<!-- keylease:end -->";
const CLAUDE: &str = "CLAUDE.md";
const AGENTS: &str = "AGENTS.md";

/// The block's text. Bump `v1` when it changes, so `--check` reports old copies.
pub(crate) fn block() -> String {
    format!(
        "{BEGIN} v1: managed by `keylease projects instructions`; edits inside are replaced -->
## Secrets (KeyLease)

This project's credentials live in KeyLease. Never ask the user for a secret value, never
print one, and never put one in a file, a command line or this conversation. Run `keylease`
from this directory: it uses this project's identity by itself.

- Find: `keylease entries search QUERY`, `keylease entries view ID`. Values are redacted;
  a field's reference is `kl://VAULT/ITEM/FIELD` (`keylease status` shows the vault id).
- Use in a command: `keylease run --env NAME=kl://VAULT/ITEM/FIELD -- COMMAND`. The value is
  in the program's environment and scrubbed from its output; do not try to print it.
- SSH and PostgreSQL without the secret: `keylease ssh HOST ...`, `keylease db psql ITEM`.
- Add: create the item without its secret (`keylease groups list`, `keylease templates list`):
  `echo '{{\"group_id\":\"...\",\"kind\":\"core.api_credential\",\"title\":\"...\"}}' |
  keylease entries create --input-json - --idempotency-key KEY`, then
  `keylease entries ask-secret ITEM_ID --field FIELD` (`password` for a login, `credential`
  for an API credential): the user types the value into KeyLease and the command returns
  once it is stored.
- Change or remove: `keylease entries update ID --if-revision N --idempotency-key KEY
  --patch-json -`, `keylease entries delete ID --if-revision N --idempotency-key KEY`, where N
  is `metadata.revision` from `entries view`. Never put a secret in a patch; replace one with
  `ask-secret`.
- Say why: add `--purpose \"...\"` to every command; the user sees it when deciding.
- Exit code 6 (`approval_required`): the user decides in `keylease approve`. Add
  `--wait-approval 110` to wait for them, or tell the user and retry the same command once
  they approve. A denial is final for that request.
{END}"
    )
}

/// Where a file's KeyLease block is, as a byte range including both markers.
fn find_block(text: &str) -> Option<std::ops::Range<usize>> {
    let start = text.find(BEGIN)?;
    let end = text[start..].find(END)? + start + END.len();
    Some(start..end)
}

/// Whether `text` imports or points to `other` (`@AGENTS.md`, `@./AGENTS.md`, or a
/// plain mention outside the KeyLease block).
fn refers_to(text: &str, other: &str) -> bool {
    let text = match find_block(text) {
        Some(range) => format!("{}{}", &text[..range.start], &text[range.end..]),
        None => text.to_owned(),
    };
    text.contains(&format!("@{other}"))
        || text.contains(&format!("@./{other}"))
        || text.contains(other)
}

/// The files the block belongs in, and a `CLAUDE.md` to create that imports `AGENTS.md`.
fn targets(root: &Path) -> (Vec<PathBuf>, Option<PathBuf>) {
    let claude = root.join(CLAUDE);
    let agents = root.join(AGENTS);
    let read = |path: &Path| fs::read_to_string(path).ok();
    match (read(&claude), read(&agents)) {
        (Some(_), Some(_)) if fs::canonicalize(&claude).ok() == fs::canonicalize(&agents).ok() => {
            (vec![agents], None)
        }
        (Some(claude_text), Some(agents_text)) => {
            if refers_to(&claude_text, AGENTS) {
                (vec![agents], None)
            } else if refers_to(&agents_text, CLAUDE) {
                (vec![claude], None)
            } else {
                // Two independent files: each tool reads only its own.
                (vec![claude, agents], None)
            }
        }
        (Some(_), None) => (vec![claude], None),
        // Claude Code reads CLAUDE.md; a one-line import keeps the block in one place.
        (None, _) => (vec![agents], Some(claude)),
    }
}

#[derive(Args)]
pub(crate) struct InstructionsArgs {
    /// The project root; default: where `.keylease.json` is, else the current directory.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Report whether the block is present and current, changing nothing.
    #[arg(long, conflicts_with = "remove")]
    check: bool,
    /// Remove the block from both files.
    #[arg(long)]
    remove: bool,
}

pub(crate) fn project_root(dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = dir {
        return Ok(dir);
    }
    let cwd = std::env::current_dir().map_err(|_| KeyLeaseError::Storage)?;
    Ok(project::find_project_file(&cwd)
        .and_then(|(path, _)| path.parent().map(Path::to_path_buf))
        .unwrap_or(cwd))
}

/// Puts the current block where it belongs, or removes it; returns what it did per file.
pub(crate) fn apply(root: &Path, remove: bool, check: bool) -> Result<Vec<Value>> {
    let (targets, import) = if remove {
        (vec![], None)
    } else {
        targets(root)
    };
    let block = block();
    let mut report = vec![];
    for name in [CLAUDE, AGENTS] {
        let path = root.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if targets.contains(&path) {
            continue;
        }
        if let Some(range) = find_block(&text) {
            let mut rest = format!("{}{}", &text[..range.start], &text[range.end..]);
            rest = rest.trim_end().to_owned() + "\n";
            if !check {
                fs::write(&path, rest).map_err(|_| KeyLeaseError::Storage)?;
            }
            report.push(
                json!({"file": path, "action": if check { "would_remove" } else { "removed" }}),
            );
        }
    }
    for path in &targets {
        let text = fs::read_to_string(path).unwrap_or_default();
        let (updated, action) = match find_block(&text) {
            Some(range) if text[range.clone()] == block => (text.clone(), "current"),
            Some(range) => (
                format!("{}{block}{}", &text[..range.start], &text[range.end..]),
                "updated",
            ),
            None if text.trim().is_empty() => (format!("{block}\n"), "added"),
            None => (format!("{}\n\n{block}\n", text.trim_end()), "added"),
        };
        if action != "current" && !check {
            fs::write(path, updated).map_err(|_| KeyLeaseError::Storage)?;
        }
        report.push(json!({
            "file": path,
            "action": if check && action != "current" { "missing_or_outdated" } else { action },
        }));
    }
    if let Some(claude) = import
        && !claude.exists()
    {
        if !check {
            fs::write(&claude, format!("@{AGENTS}\n")).map_err(|_| KeyLeaseError::Storage)?;
        }
        report.push(json!({"file": claude, "action": if check { "would_create" } else { "created_import" }}));
    }
    Ok(report)
}

pub(crate) fn instructions(args: InstructionsArgs) -> Result<()> {
    let root = project_root(args.dir)?;
    let report = apply(&root, args.remove, args.check)?;
    let stale = report.iter().any(|entry| {
        matches!(
            entry["action"].as_str(),
            Some("missing_or_outdated" | "would_remove" | "would_create")
        )
    });
    print_json(&json!({"root": root, "files": report}))?;
    if args.check && stale {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            fs::write(dir.path().join(name), text).unwrap();
        }
        dir
    }

    fn read(dir: &tempfile::TempDir, name: &str) -> String {
        fs::read_to_string(dir.path().join(name)).unwrap_or_default()
    }

    #[test]
    fn the_block_goes_into_the_file_the_other_imports() {
        let dir = setup(&[("CLAUDE.md", "@AGENTS.md\n"), ("AGENTS.md", "# Rules\n")]);
        apply(dir.path(), false, false).unwrap();
        assert!(read(&dir, "AGENTS.md").contains("## Secrets (KeyLease)"));
        assert_eq!(read(&dir, "CLAUDE.md"), "@AGENTS.md\n");

        let dir = setup(&[
            ("CLAUDE.md", "# Rules\n"),
            ("AGENTS.md", "See CLAUDE.md.\n"),
        ]);
        apply(dir.path(), false, false).unwrap();
        assert!(read(&dir, "CLAUDE.md").contains("## Secrets (KeyLease)"));
        assert!(!read(&dir, "AGENTS.md").contains("keylease:begin"));
    }

    #[test]
    fn it_updates_its_own_block_in_place_and_is_idempotent() {
        let old = format!("# Rules\n\n{BEGIN} v0 -->\nold text\n{END}\n\n## After\nkeep\n");
        let dir = setup(&[("CLAUDE.md", &old)]);
        let report = apply(dir.path(), false, false).unwrap();
        assert_eq!(report[0]["action"], "updated");
        let text = read(&dir, "CLAUDE.md");
        assert!(text.starts_with("# Rules\n\n"));
        assert!(text.ends_with("## After\nkeep\n"));
        assert!(!text.contains("old text"));
        assert_eq!(text.matches(BEGIN).count(), 1);
        assert_eq!(
            apply(dir.path(), false, false).unwrap()[0]["action"],
            "current"
        );
    }

    #[test]
    fn a_new_project_gets_agents_md_and_a_claude_md_that_imports_it() {
        let dir = setup(&[]);
        apply(dir.path(), false, false).unwrap();
        assert!(read(&dir, "AGENTS.md").contains("## Secrets (KeyLease)"));
        assert_eq!(read(&dir, "CLAUDE.md"), "@AGENTS.md\n");
    }

    #[test]
    fn a_block_left_in_the_other_file_moves_and_remove_takes_both() {
        let dir = setup(&[("CLAUDE.md", "@AGENTS.md\n"), ("AGENTS.md", "# Rules\n")]);
        let stray = format!("@AGENTS.md\n\n{}\n", block());
        fs::write(dir.path().join("CLAUDE.md"), stray).unwrap();
        apply(dir.path(), false, false).unwrap();
        assert_eq!(read(&dir, "CLAUDE.md"), "@AGENTS.md\n");
        assert!(read(&dir, "AGENTS.md").contains(BEGIN));
        apply(dir.path(), true, false).unwrap();
        assert_eq!(read(&dir, "AGENTS.md"), "# Rules\n");
    }
}
