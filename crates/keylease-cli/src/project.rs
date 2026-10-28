//! Project directories: `.keylease.json` names the agent identity and vault
//! project for a working tree, so an agent started anywhere inside it needs no
//! environment variables.

use super::*;

/// The file `keylease projects init` writes at the root of a working tree.
pub(crate) const PROJECT_FILE: &str = ".keylease.json";

/// What a project directory binds. It holds no secret: the agent's token stays
/// in `~/.keylease/clients`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectFile {
    pub agent: String,
    pub project: String,
}

/// The nearest `.keylease.json` at or above `start`.
pub(crate) fn find_project_file(start: &Path) -> Option<(PathBuf, ProjectFile)> {
    start.ancestors().find_map(|directory| {
        let path = directory.join(PROJECT_FILE);
        let metadata = fs::metadata(&path).ok()?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return None;
        }
        let file: ProjectFile = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
        Some((path, file))
    })
}

/// The agent a project directory names, if it is an agent `default_agent_token`
/// would find a token for. A file can never select the owner (`agent_desktop`).
pub(crate) fn project_agent(start: &Path) -> Option<String> {
    let (_, file) = find_project_file(start)?;
    default_agent_token(&file.agent).map(|_| file.agent)
}

/// `my_shop.v2` → `my-shop-v2`: a directory name as a project slug.
pub(crate) fn slug_from(name: &str) -> String {
    let mut slug = String::new();
    for character in name.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.truncate(63);
    slug.trim_end_matches('-').to_owned()
}

#[derive(Args)]
pub(crate) struct InitArgs {
    /// Give one agent CLI (claude, codex…) its own identity here,
    /// `agent_<agent>-<project>`. Without it, every agent working in the tree
    /// shares `agent_<project>`, so one trust answers for all of them.
    #[arg(long)]
    agent: Option<String>,
    /// The vault project; default: the directory's name.
    #[arg(long)]
    project: Option<String>,
    /// The working tree; default: the current directory.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Leave CLAUDE.md and AGENTS.md alone (see `keylease projects instructions`).
    #[arg(long)]
    no_instructions: bool,
}

/// `keylease projects init`: one command per working tree.
///
/// Creates the vault project if needed, registers the project's agent identity
/// with the baseline (or reuses it), and writes `.keylease.json`.
pub(crate) fn init(db: &Path, args: InitArgs) -> Result<()> {
    let invalid = |reason: String| KeyLeaseError::InvalidRequest { reason };
    let dir = match args.dir {
        Some(dir) => dir,
        None => std::env::current_dir().map_err(|_| KeyLeaseError::Storage)?,
    };
    let dir = fs::canonicalize(&dir)
        .map_err(|_| invalid(format!("{} is not a directory", dir.display())))?;
    let slug = match args.project {
        Some(project) => project,
        None => slug_from(
            &dir.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
    };
    let tool = args.agent.map(|tool| tool.trim().to_ascii_lowercase());
    let name = match &tool {
        Some(tool) => format!("{tool}-{slug}"),
        None => slug.clone(),
    };
    if tool.as_deref().is_some_and(|tool| !valid_client_name(tool))
        || !valid_client_name(&name)
        || name == "desktop"
    {
        return Err(invalid(format!(
            "`{name}` is not a usable agent name: letters, digits, - and _ (and not `desktop`)"
        )));
    }
    let agent_id = format!("agent_{name}");
    let file = ProjectFile {
        agent: agent_id.clone(),
        project: slug.clone(),
    };
    let file_path = dir.join(PROJECT_FILE);
    if let Ok(existing) = fs::read(&file_path)
        && serde_json::from_slice::<ProjectFile>(&existing)
            .ok()
            .as_ref()
            != Some(&file)
    {
        return Err(invalid(format!(
            "{} already names another agent or project; remove it to start over",
            file_path.display()
        )));
    }

    let service = admin_service(db)?;
    let project = service.ensure_project_admin(&slug)?;
    let token_path = trust::agent_token_path(&name)?;
    let registered = if fs::symlink_metadata(&token_path).is_ok() {
        false
    } else {
        let (registered_id, token) = service.register_client(&name)?;
        let vault_id = service.current_vault_id()?;
        service.install_agent_baseline(&registered_id, &vault_id)?;
        write_new_private_file(&token_path, token.as_bytes())?;
        true
    };
    if !file_path.exists() {
        let mut contents = serde_json::to_vec_pretty(&file).map_err(|_| KeyLeaseError::Storage)?;
        contents.push(b'\n');
        fs::write(&file_path, contents).map_err(|_| KeyLeaseError::Storage)?;
    }
    let instructions = if args.no_instructions {
        vec![]
    } else {
        instructions::apply(&dir, false, false)?
    };
    print_json(&json!({
        "project": project.slug,
        "agent_id": agent_id,
        "registered": registered,
        "project_file": file_path,
        "instructions": instructions,
        "next": format!(
            "Start {} anywhere in {}: keylease uses {agent_id} there, no environment \
             needed. Approve requests with `keylease approve`.",
            tool.as_deref().unwrap_or("any agent"),
            dir.display()
        ),
    }))
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// The item's title.
    title: String,
    /// The item's template (`keylease templates list`).
    #[arg(long, default_value = "core.api_credential")]
    kind: String,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    url: Option<String>,
    /// The vault project; default: the one `.keylease.json` names here.
    #[arg(long)]
    project: Option<String>,
    /// The group to file it in, created if missing; default: the project's slug.
    #[arg(long)]
    group: Option<String>,
}

/// `keylease add`: the owner stores a secret from the terminal, typed hidden,
/// so it never passes through an agent. Inside a project directory it is filed
/// in that project, where the project's agents can use it with approval.
pub(crate) fn add(db: &Path, args: AddArgs) -> Result<()> {
    let project = match args.project {
        Some(project) => Some(project),
        None => std::env::current_dir()
            .ok()
            .and_then(|cwd| find_project_file(&cwd))
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
    let secret = prompt("Secret (hidden): ")?;
    if secret.trim().is_empty() {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "the secret is empty".into(),
        });
    }
    let item = service.create_entry(
        &owner,
        NewEntryInput {
            favorite: false,
            group_id: group.id,
            kind: args.kind,
            title: args.title,
            project_slug: project.clone(),
            username: args.username,
            password: Some(secret.trim().to_owned()),
            url: args.url,
            notes: None,
            custom_fields: vec![],
            sections: vec![],
            totp: None,
            totp_uri: None,
        },
        &format!("add-{}", RequestId::new().0),
        false,
    )?;
    let reference = format!(
        "kl://{}/{}/password",
        service.current_vault_id()?.0,
        item.id.0
    );
    print_json(&json!({
        "id": item.id,
        "title": item.title,
        "project": project,
        "reference": reference,
        "use": format!("keylease run --env API_KEY={reference} -- COMMAND"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_names_become_project_slugs() {
        assert_eq!(slug_from("My_Shop.v2"), "my-shop-v2");
        assert_eq!(slug_from("--api--"), "api");
        assert_eq!(slug_from("shop"), "shop");
    }

    #[test]
    fn the_nearest_project_file_names_the_agent_but_never_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("src/deep");
        fs::create_dir_all(&nested).unwrap();
        assert!(find_project_file(&nested).is_none());
        let write = |agent: &str| {
            fs::write(
                dir.path().join(PROJECT_FILE),
                json!({"agent": agent, "project": "shop"}).to_string(),
            )
            .unwrap();
        };
        write("agent_claude-shop");
        assert_eq!(project_agent(&nested).as_deref(), Some("agent_claude-shop"));
        write("agent_desktop");
        assert!(project_agent(&nested).is_none());
        write("../../etc/passwd");
        assert!(project_agent(&nested).is_none());
    }
}
