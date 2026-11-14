//! Project environments (dev, staging, production…) and the Personal area.

use super::*;

const MAX_ENVIRONMENTS: usize = 16;

/// Validates an item's environment against its project.
///
/// When the project defines environments the value must name one of them
/// (slug or display name) and is stored as the slug. Otherwise any short
/// label is accepted, as before environments existed.
pub(crate) fn resolve_item_environment(
    project: Option<&VaultProject>,
    environment: Option<&str>,
) -> Result<Option<String>> {
    let Some(name) = environment.map(str::trim).filter(|name| !name.is_empty()) else {
        return Ok(None);
    };
    if let Some(project) = project.filter(|project| !project.environments.is_empty()) {
        return project
            .environment(name)
            .map(|environment| Some(environment.slug.clone()))
            .ok_or_else(|| KeyLeaseError::InvalidRequest {
                reason: format!(
                    "project {} has no environment {name:?} (it has: {})",
                    project.slug,
                    project
                        .environments
                        .iter()
                        .map(|environment| environment.slug.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
    }
    if name.len() > 64 || name.chars().any(char::is_control) {
        return Err(KeyLeaseError::InvalidRequest {
            reason: "environment must be at most 64 printable characters".into(),
        });
    }
    Ok(Some(name.to_owned()))
}

/// The environment scope written in an env file's metadata, if any.
pub(crate) fn env_file_scope(kind: &str, fields: &[ItemField]) -> Option<String> {
    if kind != "core.environment" {
        return None;
    }
    fields
        .iter()
        .find(|field| field.semantic_role.as_deref() == Some("environment_scope"))
        .and_then(|field| match &field.value {
            FieldValue::Text(value) => Some(value.trim().to_owned()),
            _ => None,
        })
        .filter(|value| !value.is_empty())
}

pub(crate) fn validate_environment_slug(slug: &str) -> Result<String> {
    let slug = slug.trim().to_ascii_lowercase();
    let valid = !slug.is_empty()
        && slug.len() <= 32
        && slug.starts_with(|character: char| character.is_ascii_lowercase())
        && slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
    if !valid {
        return Err(KeyLeaseError::InvalidRequest {
            reason:
                "environment slug must be 1-32 characters: a-z, 0-9 and -, starting with a letter"
                    .into(),
        });
    }
    Ok(slug)
}

impl KeyLeaseService {
    /// Whether `item` sits in a protected environment of its project.
    pub(crate) fn item_environment_protected(
        &self,
        vault: &UnlockedVault,
        item: &VaultItem,
    ) -> Result<bool> {
        let project = match &item.project_id {
            Some(id) => self.store.get_project(vault, id).ok(),
            None => None,
        };
        Ok(environment_is_protected(
            project.as_ref(),
            item.environment.as_deref(),
        ))
    }

    /// The project with this slug (owner commands).
    pub fn get_project_by_slug(&self, slug: &str) -> Result<VaultProject> {
        self.with_vault(|vault| self.project_by_slug(vault, slug))
    }

    fn project_by_slug(&self, vault: &UnlockedVault, slug: &str) -> Result<VaultProject> {
        self.store
            .list_projects(vault)?
            .into_iter()
            .find(|project| project.slug == slug)
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: format!("project {slug}"),
            })
    }

    /// Adds an environment to a project, or updates its name and
    /// protection (owner command).
    pub fn set_project_environment(
        &self,
        project_slug: &str,
        slug: &str,
        name: Option<&str>,
        protected: bool,
    ) -> Result<VaultProject> {
        let slug = validate_environment_slug(slug)?;
        let name = name.map(str::trim).filter(|name| !name.is_empty());
        if name.is_some_and(|name| name.len() > 64 || name.chars().any(char::is_control)) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "environment name must be at most 64 printable characters".into(),
            });
        }
        self.update_project_environments(project_slug, |environments| {
            match environments
                .iter_mut()
                .find(|environment| environment.slug == slug)
            {
                Some(existing) => {
                    if let Some(name) = name {
                        existing.name = name.to_owned();
                    }
                    existing.protected = protected;
                }
                None => {
                    if environments.len() >= MAX_ENVIRONMENTS {
                        return Err(KeyLeaseError::InvalidRequest {
                            reason: format!(
                                "a project has at most {MAX_ENVIRONMENTS} environments"
                            ),
                        });
                    }
                    environments.push(ProjectEnvironment {
                        name: name.unwrap_or(&slug).to_owned(),
                        slug: slug.clone(),
                        protected,
                    });
                }
            }
            Ok(())
        })
    }

    /// Removes an environment that no item uses (owner command).
    pub fn remove_project_environment(
        &self,
        project_slug: &str,
        slug: &str,
    ) -> Result<VaultProject> {
        let in_use = self.with_vault(|vault| {
            let project = self.project_by_slug(vault, project_slug)?;
            Ok(self.store.list_items(vault)?.iter().any(|item| {
                item.project_id.as_ref() == Some(&project.id)
                    && item
                        .environment
                        .as_deref()
                        .is_some_and(|environment| environment.eq_ignore_ascii_case(slug))
            }))
        })?;
        if in_use {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!("items still use environment {slug}; move them first"),
            });
        }
        self.update_project_environments(project_slug, |environments| {
            let before = environments.len();
            environments.retain(|environment| environment.slug != slug);
            if environments.len() == before {
                return Err(KeyLeaseError::NotFound {
                    resource: format!("environment {slug}"),
                });
            }
            Ok(())
        })
    }

    fn update_project_environments(
        &self,
        project_slug: &str,
        change: impl FnOnce(&mut Vec<ProjectEnvironment>) -> Result<()>,
    ) -> Result<VaultProject> {
        self.with_vault(|vault| {
            let mut project = self.project_by_slug(vault, project_slug)?;
            change(&mut project.environments)?;
            let expected = project.revision;
            project.revision += 1;
            project.updated_at = Utc::now();
            let idempotency_key = random_token("project-env");
            let request_material = operation_material(&serde_json::json!({
                "operation":"project:environments",
                "project":project.id,
                "environments":project.environments,
            }))?;
            self.store.put_project(
                vault,
                &project,
                Some(expected),
                MutationContext {
                    actor: "owner",
                    idempotency_key: &idempotency_key,
                    request_material: &request_material,
                    audit_event: None,
                },
            )?;
            Ok(project)
        })
    }

    /// Resolves a named reference `PROJECT[/ENVIRONMENT]/ITEM` (the part of
    /// `kl://shop/production/stripe#secret_key` before `#`) to an item.
    ///
    /// The item is matched by title, case-insensitively. Personal items are
    /// never matched for agents.
    pub(crate) fn resolve_named_item(
        &self,
        vault: &UnlockedVault,
        actor: &ActorContext,
        path: &str,
    ) -> Result<ItemId> {
        let not_found = || KeyLeaseError::NotFound {
            resource: format!("kl://{path}"),
        };
        let parts: Vec<&str> = path.split('/').collect();
        let (project_slug, environment, title) = match parts.as_slice() {
            [project, item] => (*project, None, *item),
            [project, environment, item] => (*project, Some(*environment), *item),
            _ => {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "a named reference is kl://PROJECT[/ENVIRONMENT]/ITEM#FIELD".into(),
                });
            }
        };
        let project = self
            .project_by_slug(vault, project_slug)
            .map_err(|_| not_found())?;
        let environment = match environment {
            Some(name) => resolve_item_environment(Some(&project), Some(name))?,
            None => None,
        };
        let owner = self.is_local_owner(&actor.agent_id)?;
        let mut matches = self.store.list_items(vault)?.into_iter().filter(|item| {
            item.project_id.as_ref() == Some(&project.id)
                && item.status == ItemStatus::Active
                && (owner || !item.personal)
                && item.title.eq_ignore_ascii_case(title)
                && (environment.is_none()
                    || item.environment.as_deref().is_some_and(|value| {
                        Some(value.to_ascii_lowercase())
                            == environment.as_ref().map(|e| e.to_ascii_lowercase())
                    }))
        });
        let item = matches.next().ok_or_else(not_found)?;
        if matches.next().is_some() {
            return Err(KeyLeaseError::InvalidRequest {
                reason: format!(
                    "kl://{path} matches more than one item; add the environment or rename one"
                ),
            });
        }
        Ok(item.id)
    }
}

/// The field key a reference names: the key itself, an `.env` variable name
/// (stored as `env.NAME`), or a field label.
pub(crate) fn resolve_field_key(item: &VaultItem, name: &str) -> Option<String> {
    if name == "notes" {
        return Some(name.to_owned());
    }
    item.fields
        .iter()
        .find(|field| field.key == name)
        .or_else(|| {
            item.fields
                .iter()
                .find(|field| field.key.strip_prefix("env.") == Some(name))
        })
        .or_else(|| {
            item.fields
                .iter()
                .find(|field| field.label.eq_ignore_ascii_case(name))
        })
        .map(|field| field.key.clone())
}
