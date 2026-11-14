//! Groups, entries, content, migrations, reveal and history.

use super::*;

impl KeyLeaseService {
    pub fn create_group(&self, name: &str, parent_id: Option<GroupId>) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            validate_group(name, parent_id.as_ref(), &self.store.list_groups(vault)?)?;
            let now = Utc::now();
            let group = VaultGroup {
                id: GroupId::new(),
                vault_id: vault.vault_id.clone(),
                parent_id,
                name: name.into(),
                purpose: GroupPurpose::User,
                sort_order: None,
                revision: 1,
                created_at: now,
                updated_at: now,
            };
            self.store.put_group(vault, &group, Some(0), None)?;
            Ok(group)
        })
    }
    pub fn list_groups(&self) -> Result<Vec<VaultGroup>> {
        self.with_vault(|vault| self.store.list_groups(vault))
    }
    pub fn create_group_authorized(
        &self,
        actor: &ActorContext,
        name: &str,
        parent_id: Option<GroupId>,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            validate_group(name, None, &[])?;
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"group:create",
                "actor":actor.agent_id,
                "name":name,
                "parent_id":parent_id,
            }))?;
            self.authorize_vault(
                vault,
                actor,
                "group:create",
                &format!("kl://{}/groups", vault.vault_id.0),
                serde_json::json!({"name":name,"parent_id":parent_id}),
            )?;
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return self.store.get_group(vault, &GroupId(replay.item_id.0));
            }
            validate_group(name, parent_id.as_ref(), &self.store.list_groups(vault)?)?;
            let now = Utc::now();
            let group = VaultGroup {
                id: GroupId::new(),
                vault_id: vault.vault_id.clone(),
                parent_id,
                name: name.into(),
                purpose: GroupPurpose::User,
                sort_order: None,
                revision: 1,
                created_at: now,
                updated_at: now,
            };
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "group:create",
                    &group.id.0,
                    "allow",
                    "success",
                    vec!["name".into()],
                );
                self.store.put_group(
                    vault,
                    &group,
                    Some(0),
                    Some(MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    }),
                )?;
            } else {
                self.audit_vault(
                    actor,
                    "group:create",
                    &group.id.0,
                    "allow",
                    "dry_run",
                    vec!["name".into()],
                )?;
            }
            Ok(group)
        })
    }
    pub fn list_groups_authorized(&self, actor: &ActorContext) -> Result<Vec<VaultGroup>> {
        self.with_vault(|vault| {
            self.authorize_vault(
                vault,
                actor,
                "entry:search",
                &format!("kl://{}", vault.vault_id.0),
                Value::Object(Default::default()),
            )?;
            self.store.list_groups(vault)
        })
    }

    pub fn create_agent_new_item_handoff_authorized(
        &self,
        actor: &ActorContext,
        mut input: AgentNewItemHandoffInput,
    ) -> Result<AgentNewItemHandoffReceipt> {
        self.with_vault(|vault| {
            if !self.desktop_owner_only(&actor.agent_id)? {
                return Err(KeyLeaseError::Denied {
                    reason: "only the local desktop owner may create an agent handoff".into(),
                });
            }
            validate_agent_new_item_handoff(vault, &self.store, &mut input)?;
            let handoff_id = random_token("handoff_");
            let expires_at = Instant::now() + AGENT_HANDOFF_TTL;
            let expires_at_utc = Utc::now() + Duration::seconds(AGENT_HANDOFF_TTL.as_secs() as i64);
            let mut handoffs = self
                .agent_handoffs
                .lock()
                .map_err(|_| KeyLeaseError::Storage)?;
            let now = Instant::now();
            handoffs.retain(|_, handoff| handoff.expires_at > now);
            if handoffs.len() >= MAX_AGENT_HANDOFFS
                && let Some(oldest) = handoffs
                    .iter()
                    .min_by_key(|(_, handoff)| handoff.expires_at)
                    .map(|(id, _)| id.clone())
            {
                handoffs.remove(&oldest);
            }
            handoffs.insert(
                handoff_id.clone(),
                AgentNewItemHandoff {
                    creator_agent_id: actor.agent_id.clone(),
                    vault_id: vault.vault_id.clone(),
                    input,
                    expires_at,
                    expires_at_utc,
                },
            );
            Ok(AgentNewItemHandoffReceipt {
                protocol_version: AGENT_NEW_ITEM_PROTOCOL_VERSION,
                command: format!("keylease agent new-item {handoff_id}"),
                handoff_id,
                expires_at: expires_at_utc,
            })
        })
    }

    pub fn get_agent_new_item_handoff_authorized(
        &self,
        actor: &ActorContext,
        handoff_id: &str,
    ) -> Result<AgentNewItemGuide> {
        self.with_vault(|vault| {
            // Matches the check on the create side. The guide echoes the recipe
            // and context the handoff was created with, so reading one is part
            // of the same desktop-only workflow.
            if !self.desktop_owner_only(&actor.agent_id)? {
                return Err(KeyLeaseError::Denied {
                    reason: "only the local desktop owner may read an agent handoff".into(),
                });
            }
            let (input, expires_at) = {
                let mut handoffs = self
                    .agent_handoffs
                    .lock()
                    .map_err(|_| KeyLeaseError::Storage)?;
                let now = Instant::now();
                handoffs.retain(|_, handoff| handoff.expires_at > now);
                let handoff = handoffs.get(handoff_id).ok_or_else(|| {
                    KeyLeaseError::InvalidRequest {
                        reason: "agent handoff is missing or expired; return to KeyLease and copy a new command"
                            .into(),
                    }
                })?;
                if handoff.creator_agent_id != actor.agent_id {
                    return Err(KeyLeaseError::Denied {
                        reason: "agent handoff belongs to a different local client".into(),
                    });
                }
                if handoff.vault_id != vault.vault_id {
                    return Err(KeyLeaseError::Denied {
                        reason: "agent handoff belongs to a different vault; return to KeyLease and copy a new command"
                            .into(),
                    });
                }
                (handoff.input.clone(), handoff.expires_at_utc)
            };
            build_agent_new_item_guide(vault, &self.store, handoff_id, input, expires_at)
        })
    }
    pub fn reorder_groups_authorized(
        &self,
        actor: &ActorContext,
        parent_id: Option<GroupId>,
        ordered_ids: &[GroupId],
        expected_revisions: &BTreeMap<String, u64>,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<Vec<VaultGroup>> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            self.authorize_vault(
                vault,
                actor,
                "group:update",
                &format!("kl://{}/groups", vault.vault_id.0),
                serde_json::json!({"parent_id":parent_id,"ordered_ids":ordered_ids}),
            )?;
            let groups = self.store.list_groups(vault)?;
            let mut siblings: Vec<VaultGroup> = groups
                .into_iter()
                .filter(|group| group.parent_id == parent_id)
                .collect();
            let mut actual: Vec<String> = siblings.iter().map(|group| group.id.0.clone()).collect();
            let mut requested: Vec<String> = ordered_ids.iter().map(|id| id.0.clone()).collect();
            actual.sort();
            requested.sort();
            if actual != requested {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "ordered_ids must contain every sibling exactly once".into(),
                });
            }
            for group in &siblings {
                let expected = expected_revisions
                    .get(&group.id.0)
                    .copied()
                    .ok_or_else(|| KeyLeaseError::InvalidRequest {
                        reason: format!("missing revision for {}", group.id.0),
                    })?;
                if group.revision != expected {
                    return Err(KeyLeaseError::RevisionConflict {
                        expected,
                        actual: group.revision,
                        retryable: false,
                    });
                }
            }
            siblings.sort_by_key(|group| {
                ordered_ids
                    .iter()
                    .position(|id| id == &group.id)
                    .unwrap_or(usize::MAX)
            });
            for (index, group) in siblings.iter_mut().enumerate() {
                let expected = group.revision;
                group.sort_order = Some(index as u32);
                group.revision += 1;
                group.updated_at = Utc::now();
                if !dry_run {
                    self.store.put_group(vault, group, Some(expected), None)?;
                }
            }
            Ok(siblings)
        })
    }
    pub fn update_group(
        &self,
        id: &GroupId,
        name: &str,
        expected_revision: u64,
    ) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            let groups = self.store.list_groups(vault)?;
            validate_group(name, None, &groups)?;
            let mut group = groups.into_iter().find(|g| &g.id == id).ok_or_else(|| {
                KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                }
            })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            group.name = name.into();
            group.revision += 1;
            group.updated_at = Utc::now();
            self.store
                .put_group(vault, &group, Some(expected_revision), None)?;
            Ok(group)
        })
    }
    pub fn delete_group(&self, id: &GroupId, expected_revision: u64) -> Result<()> {
        self.with_vault(|vault| {
            let groups = self.store.list_groups(vault)?;
            let group = groups.iter().find(|group| &group.id == id).ok_or_else(|| {
                KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                }
            })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            if groups
                .iter()
                .any(|group| group.parent_id.as_ref() == Some(id))
                || self
                    .store
                    .list_items(vault)?
                    .iter()
                    .any(|item| &item.group_id == id)
            {
                return Err(KeyLeaseError::Denied {
                    reason: "group must be empty before deletion".into(),
                });
            }
            self.store.delete_group(vault, id, expected_revision, None)
        })
    }
    pub fn update_group_authorized(
        &self,
        actor: &ActorContext,
        id: &GroupId,
        name: &str,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<VaultGroup> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"group:update",
                "actor":actor.agent_id,
                "id":id,
                "name":name,
                "expected_revision":expected_revision,
            }))?;
            let resource = format!("kl://{}/group/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                "group:update",
                &resource,
                serde_json::json!({"name":name,"expected_revision":expected_revision}),
            )?;
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return self.store.get_group(vault, &GroupId(replay.item_id.0));
            }
            let groups = self.store.list_groups(vault)?;
            validate_group(name, None, &groups)?;
            let mut group = groups
                .into_iter()
                .find(|group| &group.id == id)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            group.name = name.into();
            group.revision += 1;
            group.updated_at = Utc::now();
            if dry_run {
                self.audit_vault(
                    actor,
                    "group:update",
                    &resource,
                    "allow",
                    "dry_run",
                    vec!["name".into()],
                )?;
            } else {
                let audit = self.vault_audit_event(
                    actor,
                    "group:update",
                    &resource,
                    "allow",
                    "success",
                    vec!["name".into()],
                );
                self.store.put_group(
                    vault,
                    &group,
                    Some(expected_revision),
                    Some(MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    }),
                )?;
            }
            Ok(group)
        })
    }
    pub fn delete_group_authorized(
        &self,
        actor: &ActorContext,
        id: &GroupId,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<()> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"group:delete",
                "actor":actor.agent_id,
                "id":id,
                "expected_revision":expected_revision,
            }))?;
            let resource = format!("kl://{}/group/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                "group:delete",
                &resource,
                serde_json::json!({"expected_revision":expected_revision}),
            )?;
            if !dry_run
                && self
                    .store
                    .mutation_replay(vault, idempotency_key, &request_material)?
                    .is_some()
            {
                return Ok(());
            }
            let groups = self.store.list_groups(vault)?;
            let group = groups.iter().find(|group| &group.id == id).ok_or_else(|| {
                KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                }
            })?;
            if group.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: group.revision,
                    retryable: false,
                });
            }
            if groups
                .iter()
                .any(|group| group.parent_id.as_ref() == Some(id))
                || self
                    .store
                    .list_items(vault)?
                    .iter()
                    .any(|item| &item.group_id == id)
            {
                return Err(KeyLeaseError::Denied {
                    reason: "group must be empty before deletion".into(),
                });
            }
            if dry_run {
                self.audit_vault(actor, "group:delete", &resource, "allow", "dry_run", vec![])
            } else {
                let audit = self.vault_audit_event(
                    actor,
                    "group:delete",
                    &resource,
                    "allow",
                    "success",
                    vec![],
                );
                self.store.delete_group(
                    vault,
                    id,
                    expected_revision,
                    Some(MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    }),
                )
            }
        })
    }

    pub fn create_entry(
        &self,
        actor: &ActorContext,
        mut input: NewEntryInput,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<ItemMetadata> {
        self.with_vault(|vault| {
            normalize_totp(&mut input.totp, &mut input.totp_uri)?;
            canonicalize_template_fields(&input.kind, &mut input.custom_fields);
            validate_custom_fields(&input.custom_fields)?;
            validate_sections(&input.sections, &input.custom_fields)?;
            validate_specialized_item(&input.kind, &input.sections, &input.custom_fields)?;
            validate_item_title(&input.title)?;
            let project_id = resolve_project_id(
                &self.store.list_projects(vault)?,
                input.project_slug.as_deref(),
            )?;
            validate_idempotency_key(idempotency_key)?;
            let request_value = serde_json::to_value(&input).map_err(|_| KeyLeaseError::Storage)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"entry:create",
                "actor":actor.agent_id,
                "input":request_value,
            }))?;
            let resource = format!("kl://{}/group/{}", vault.vault_id.0, input.group_id.0);
            self.authorize_vault(vault, actor, "entry:create", &resource, request_value)?;
            if input.password.is_some()
                || input.custom_fields.iter().any(|field| {
                    field.protected
                        || matches!(
                            field.sensitivity,
                            Sensitivity::Secret | Sensitivity::HighlySensitive
                        )
                })
            {
                self.authorize_vault(
                    vault,
                    actor,
                    "entry:update_protected_fields",
                    &resource,
                    serde_json::json!({"operation":"set_new_protected_fields","project_slug":input.project_slug}),
                )?;
            }
            if input.totp.is_some() {
                self.authorize_vault(
                    vault,
                    actor,
                    "entry:update_totp",
                    &resource,
                    serde_json::json!({"operation":"set_new_totp","project_slug":input.project_slug}),
                )?;
            }
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return Ok(self
                    .store
                    .get_item_at_revision(vault, &replay.item_id, replay.result_revision)?
                    .metadata());
            }
            if !self
                .store
                .list_groups(vault)?
                .iter()
                .any(|group| group.id == input.group_id)
            {
                return Err(KeyLeaseError::NotFound {
                    resource: input.group_id.0.clone(),
                });
            }
            let now = Utc::now();
            let mut fields = input.custom_fields.clone();
            if let Some(v) = &input.username {
                fields.push(field(
                    "username",
                    "Username",
                    FieldValue::Text(v.clone()),
                    Sensitivity::PrivateMetadata,
                    false,
                ));
            }
            if let Some(v) = &input.password {
                fields.push(field(
                    "password",
                    "Password",
                    FieldValue::Concealed(v.clone()),
                    Sensitivity::Secret,
                    true,
                ));
            }
            if let Some(value) = &input.totp {
                fields.push(field(
                    "otp",
                    "One-time password",
                    FieldValue::Totp(value.clone()),
                    Sensitivity::Secret,
                    true,
                ));
            }
            let item = VaultItem {
                id: ItemId::new(),
                vault_id: vault.vault_id.clone(),
                group_id: input.group_id.clone(),
                kind: validate_kind(&input.kind)?,
                title: input.title.clone(),
                sections: input.sections.clone(),
                fields,
                urls: input
                    .url
                    .iter()
                    .map(|url| ItemUrl {
                        label: None,
                        url: url.clone(),
                    })
                    .collect(),
                tags: vec![],
                favorite: input.favorite,
                attachments: vec![],
                notes: input.notes.clone(),
                template_version: item_kind(&input.kind)
                    .map(|definition| definition.template_version)
                    .unwrap_or(1),
                project_id,
                agent_access: AgentAccess::None,
                content_metadata: None,
                schema_version: 1,
                revision: 1,
                created_at: now,
                updated_at: now,
                secret_changed_at: input.password.as_ref().map(|_| now),
                expires_at: None,
                rotation_interval_days: None,
                issuer: None,
                environment: None,
                owner: None,
                status: ItemStatus::Active,
                extensions: Default::default(),
            };
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "entry:create",
                    &item.id.0,
                    "allow",
                    "success",
                    vec!["item".into()],
                );
                self.store.put_item(
                    vault,
                    &item,
                    Some(0),
                    MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    },
                )?;
            } else {
                self.audit_vault(
                    actor,
                    "entry:create",
                    &item.id.0,
                    "allow",
                    "dry_run",
                    vec!["item".into()],
                )?;
            }
            Ok(item.metadata())
        })
    }

    pub fn update_entry(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        mut patch: EntryPatch,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<ItemMetadata> {
        self.with_vault(|vault| {
            normalize_totp(&mut patch.totp, &mut patch.totp_uri)?;
            validate_idempotency_key(idempotency_key)?;
            let current_item = self.store.get_item(vault, id)?;
            refuse_shared_copy(&current_item)?;
            if let Some(fields) = &mut patch.custom_fields {
                canonicalize_template_fields(&current_item.kind, fields);
                validate_custom_fields(fields)?;
            }
            if !patch.field_updates.is_empty() {
                canonicalize_template_fields(&current_item.kind, &mut patch.field_updates);
                validate_custom_fields(&patch.field_updates)?;
            }
            validate_removed_field_ids(&patch.remove_field_ids)?;
            if let Some(missing) = patch.remove_field_ids.iter().find(|field_id| {
                !current_item
                    .fields
                    .iter()
                    .any(|field| &field.id == *field_id)
            }) {
                return Err(KeyLeaseError::NotFound {
                    resource: missing.0.clone(),
                });
            }
            if let Some(title) = &patch.title {
                validate_item_title(title)?;
            }
            if patch.project_slug.is_some() && patch.clear_project {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "project_slug and clear_project are mutually exclusive".into(),
                });
            }
            let requested_project_id = if let Some(slug) = patch.project_slug.as_deref() {
                Some(resolve_project_id(
                    &self.store.list_projects(vault)?,
                    Some(slug),
                )?)
            } else {
                None
            };
            let arguments = serde_json::to_value(&patch).map_err(|_| KeyLeaseError::Storage)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"entry:update",
                "actor":actor.agent_id,
                "item_id":id,
                "expected_revision":expected_revision,
                "patch":arguments,
            }))?;
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            let has_standard_fields = patch.title.is_some()
                || patch.project_slug.is_some()
                || patch.clear_project
                || patch.username.is_some()
                || patch.url.is_some()
                || patch.notes.is_some()
                || patch.favorite.is_some()
                || patch.custom_fields.as_ref().is_some_and(|fields| {
                    fields.iter().any(|field| !field_requires_protection(field))
                })
                || patch
                    .field_updates
                    .iter()
                    .any(|field| !field_requires_protection(field))
                || patch.sections.is_some()
                || !patch.remove_field_ids.is_empty();
            let replacement_removes_protected =
                patch.custom_fields.as_ref().is_some_and(|fields| {
                    current_item.fields.iter().any(|existing| {
                        !matches!(existing.key.as_str(), "username" | "password" | "otp")
                            && field_requires_protection(existing)
                            && fields
                                .iter()
                                .find(|field| field.id == existing.id)
                                .is_none_or(|field| !field_requires_protection(field))
                    })
                });
            let updates_downgrade_protected = patch.field_updates.iter().any(|updated| {
                !field_requires_protection(updated)
                    && current_item
                        .fields
                        .iter()
                        .find(|existing| existing.id == updated.id)
                        .is_some_and(field_requires_protection)
            });
            let explicitly_removes_protected = current_item.fields.iter().any(|field| {
                field_requires_protection(field) && patch.remove_field_ids.contains(&field.id)
            });
            let has_protected_fields = patch.password.is_some()
                || patch
                    .custom_fields
                    .as_ref()
                    .is_some_and(|fields| fields.iter().any(field_requires_protection))
                || patch.field_updates.iter().any(field_requires_protection)
                || replacement_removes_protected
                || updates_downgrade_protected
                || explicitly_removes_protected;
            if !has_standard_fields
                && !has_protected_fields
                && patch.totp.is_none()
                && patch.group_id.is_none()
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "entry patch does not change any fields".into(),
                });
            }
            for required_capability in [
                has_standard_fields.then_some("entry:update_standard_fields"),
                has_protected_fields.then_some("entry:update_protected_fields"),
                patch.totp.is_some().then_some("entry:update_totp"),
                patch.group_id.is_some().then_some("entry:move"),
            ]
            .into_iter()
            .flatten()
            {
                self.authorize_vault(
                    vault,
                    actor,
                    required_capability,
                    &resource,
                    arguments.clone(),
                )?;
            }
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                if replay.item_id != *id {
                    return Err(KeyLeaseError::IdempotencyConflict);
                }
                return Ok(self
                    .store
                    .get_item_at_revision(vault, id, replay.result_revision)?
                    .metadata());
            }
            if let Some(group_id) = &patch.group_id
                && !self
                    .store
                    .list_groups(vault)?
                    .iter()
                    .any(|group| &group.id == group_id)
            {
                return Err(KeyLeaseError::NotFound {
                    resource: group_id.0.clone(),
                });
            }
            let mut item = current_item;
            if item.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: item.revision,
                    retryable: false,
                });
            }
            let mut changed = vec![];
            if let Some(v) = patch.title {
                item.title = v;
                changed.push("title".into())
            }
            if let Some(v) = patch.username {
                upsert(
                    &mut item.fields,
                    "username",
                    FieldValue::Text(v),
                    Sensitivity::PrivateMetadata,
                    false,
                );
                changed.push("username".into())
            }
            if let Some(v) = patch.password {
                upsert(
                    &mut item.fields,
                    "password",
                    FieldValue::Concealed(v),
                    Sensitivity::Secret,
                    true,
                );
                item.secret_changed_at = Some(Utc::now());
                changed.push("password".into())
            }
            if let Some(v) = patch.url {
                item.urls = vec![ItemUrl {
                    label: None,
                    url: v,
                }];
                changed.push("url".into())
            }
            if let Some(v) = patch.notes {
                item.notes = Some(v);
                changed.push("notes".into())
            }
            if let Some(v) = patch.group_id {
                item.group_id = v;
                changed.push("group_id".into())
            }
            if let Some(project_id) = requested_project_id {
                item.project_id = project_id;
                changed.push("project_id".into())
            } else if patch.clear_project {
                item.project_id = None;
                changed.push("project_id".into())
            }
            if let Some(v) = patch.favorite {
                item.favorite = v;
                item.extensions.remove("onepux.favorite_index");
                changed.push("favorite".into())
            }
            if let Some(v) = patch.totp {
                upsert(
                    &mut item.fields,
                    "otp",
                    FieldValue::Totp(v),
                    Sensitivity::Secret,
                    true,
                );
                changed.push("otp".into())
            }
            if let Some(fields) = patch.custom_fields {
                item.fields
                    .retain(|field| matches!(field.key.as_str(), "username" | "password" | "otp"));
                changed.extend(fields.iter().map(|field| field.key.clone()));
                item.fields.extend(fields);
            }
            for field in patch.field_updates {
                changed.push(field.key.clone());
                if let Some(existing) = item
                    .fields
                    .iter_mut()
                    .find(|existing| existing.id == field.id || existing.key == field.key)
                {
                    *existing = field;
                } else {
                    item.fields.push(field);
                }
            }
            if !patch.remove_field_ids.is_empty() {
                item.fields
                    .retain(|field| !patch.remove_field_ids.contains(&field.id));
                for section in &mut item.sections {
                    section
                        .field_ids
                        .retain(|field_id| !patch.remove_field_ids.contains(field_id));
                }
                changed.push("removed_fields".into());
            }
            if let Some(sections) = patch.sections {
                item.sections = sections;
                changed.push("sections".into());
            }
            let custom_fields = item
                .fields
                .iter()
                .filter(|field| !matches!(field.key.as_str(), "username" | "password" | "otp"))
                .cloned()
                .collect::<Vec<_>>();
            validate_custom_fields(&custom_fields)?;
            validate_sections(&item.sections, &item.fields)?;
            validate_specialized_item(&item.kind, &item.sections, &item.fields)?;
            item.revision += 1;
            item.updated_at = Utc::now();
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "entry:update",
                    &id.0,
                    "allow",
                    "success",
                    changed,
                );
                self.store.put_item(
                    vault,
                    &item,
                    Some(expected_revision),
                    MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    },
                )?;
            } else {
                self.audit_vault(actor, "entry:update", &id.0, "allow", "dry_run", changed)?;
            }
            Ok(item.metadata())
        })
    }

    pub fn search_entries(&self, actor: &ActorContext, query: &str) -> Result<Vec<ItemMetadata>> {
        self.search_entries_scoped(actor, query, None, false)
    }

    pub fn search_entries_scoped(
        &self,
        actor: &ActorContext,
        query: &str,
        project_slug: Option<&str>,
        unassigned: bool,
    ) -> Result<Vec<ItemMetadata>> {
        self.with_vault(|vault| {
            if project_slug.is_some() && unassigned {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "project_slug and unassigned are mutually exclusive".into(),
                });
            }
            let project_id = resolve_project_id(
                &self.store.list_projects(vault)?,
                project_slug,
            )?;
            self.authorize_vault(
                vault,
                actor,
                "entry:search",
                &format!("kl://{}", vault.vault_id.0),
                serde_json::json!({"query":query,"project_slug":project_slug,"unassigned":unassigned}),
            )?;
            let q = query.to_lowercase();
            let result = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|i| {
                    if unassigned { i.project_id.is_none() }
                    else { project_id.as_ref().is_none_or(|id| i.project_id.as_ref() == Some(id)) }
                })
                .filter(|i| {
                    i.title.to_lowercase().contains(&q)
                        || i.metadata()
                            .username
                            .is_some_and(|u| u.to_lowercase().contains(&q))
                        || i.urls.iter().any(|u| u.url.to_lowercase().contains(&q))
                })
                .map(|i| i.metadata())
                .collect();
            self.audit_vault(
                actor,
                "entry:search",
                &vault.vault_id.0,
                "allow",
                "success",
                vec![],
            )?;
            Ok(result)
        })
    }
    pub fn get_entry_metadata(&self, actor: &ActorContext, id: &ItemId) -> Result<ItemMetadata> {
        self.with_vault(|vault| {
            self.authorize_vault(
                vault,
                actor,
                "entry:read_metadata",
                &format!("kl://{}/{}", vault.vault_id.0, id.0),
                Value::Object(Default::default()),
            )?;
            let metadata = self.store.get_item(vault, id)?.metadata();
            self.audit_vault(
                actor,
                "entry:read_metadata",
                &id.0,
                "allow",
                "success",
                vec![],
            )?;
            Ok(metadata)
        })
    }

    pub fn migration_status(&self, actor: &ActorContext) -> Result<MigrationStatus> {
        self.with_vault(|vault| {
            self.ensure_migration_owner(actor)?;
            let records = self.store.list_migration_records()?;
            let already_handled = records
                .iter()
                .any(|record| record.migration_id == KDBX_RECLASSIFY_MIGRATION_ID);
            let preview = self.kdbx_reclassify_preview(vault)?;
            let pending = if !already_handled && !preview.proposals.is_empty() {
                vec![preview]
            } else {
                vec![]
            };
            let history = records
                .into_iter()
                .map(|record| MigrationHistoryEntry {
                    migration_id: record.migration_id,
                    version: record.version,
                    state: record.state,
                    item_count: record.item_count,
                    applied_at: record.applied_at,
                    rolled_back_at: record.rolled_back_at,
                })
                .collect();
            Ok(MigrationStatus {
                framework_version: MIGRATION_FRAMEWORK_VERSION,
                pending,
                history,
            })
        })
    }

    pub fn preview_migration(
        &self,
        actor: &ActorContext,
        migration_id: &str,
    ) -> Result<MigrationPreview> {
        self.with_vault(|vault| {
            self.ensure_migration_owner(actor)?;
            match migration_id {
                KDBX_RECLASSIFY_MIGRATION_ID => self.kdbx_reclassify_preview(vault),
                _ => Err(KeyLeaseError::NotFound {
                    resource: migration_id.into(),
                }),
            }
        })
    }

    pub fn apply_migration(
        &self,
        actor: &ActorContext,
        migration_id: &str,
        preview_digest: &str,
    ) -> Result<MigrationApplyResult> {
        self.with_vault(|vault| {
            self.ensure_migration_owner(actor)?;
            let preview = match migration_id {
                KDBX_RECLASSIFY_MIGRATION_ID => self.kdbx_reclassify_preview(vault)?,
                _ => {
                    return Err(KeyLeaseError::NotFound {
                        resource: migration_id.into(),
                    });
                }
            };
            if preview.preview_digest != preview_digest {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: 0,
                    actual: 0,
                    retryable: true,
                });
            }
            let proposal_by_id = preview
                .proposals
                .iter()
                .map(|proposal| (&proposal.item_id, proposal))
                .collect::<HashMap<_, _>>();
            let now = Utc::now();
            let mut items = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter_map(|mut item| {
                    let proposal = proposal_by_id.get(&item.id)?;
                    if item.revision != proposal.expected_revision {
                        return Some(Err(KeyLeaseError::RevisionConflict {
                            expected: proposal.expected_revision,
                            actual: item.revision,
                            retryable: true,
                        }));
                    }
                    item.extensions.insert(
                        "migration.kdbx_reclassify_v1.previous_kind".into(),
                        serde_json::json!(item.kind),
                    );
                    item.extensions.insert(
                        "migration.kdbx_reclassify_v1.applied_at".into(),
                        serde_json::json!(now),
                    );
                    item.kind = proposal.proposed_kind.clone();
                    item.template_version = item_kind(&item.kind)
                        .map(|template| template.template_version)
                        .unwrap_or(1);
                    canonicalize_template_fields(&item.kind, &mut item.fields);
                    item.revision += 1;
                    item.updated_at = now;
                    Some(Ok(item))
                })
                .collect::<Result<Vec<_>>>()?;
            items.sort_by(|left, right| left.id.0.cmp(&right.id.0));
            let audit = self.vault_audit_event(
                actor,
                "migration:apply",
                migration_id,
                "allow",
                "success",
                vec!["kind".into(), "semantic_role".into(), "sensitivity".into()],
            );
            let count = self.store.apply_item_migration(
                vault,
                migration_id,
                preview.version,
                preview_digest,
                &items,
                &audit,
            )?;
            Ok(MigrationApplyResult {
                migration_id: migration_id.into(),
                state: "applied".into(),
                item_count: count,
                checkpoint_available: true,
            })
        })
    }

    pub fn rollback_migration(
        &self,
        actor: &ActorContext,
        migration_id: &str,
    ) -> Result<MigrationApplyResult> {
        self.with_vault(|vault| {
            self.ensure_migration_owner(actor)?;
            let audit = self.vault_audit_event(
                actor,
                "migration:rollback",
                migration_id,
                "allow",
                "success",
                vec!["items".into()],
            );
            let count = self
                .store
                .rollback_item_migration(vault, migration_id, &audit)?;
            Ok(MigrationApplyResult {
                migration_id: migration_id.into(),
                state: "rolled_back".into(),
                item_count: count,
                checkpoint_available: false,
            })
        })
    }

    pub(crate) fn ensure_migration_owner(&self, actor: &ActorContext) -> Result<()> {
        if !self.desktop_owner_only(&actor.agent_id)? {
            return Err(KeyLeaseError::Denied {
                reason: "only the local desktop owner may manage vault migrations".into(),
            });
        }
        Ok(())
    }

    pub(crate) fn kdbx_reclassify_preview(
        &self,
        vault: &UnlockedVault,
    ) -> Result<MigrationPreview> {
        let mut proposals = self
            .store
            .list_items(vault)?
            .into_iter()
            .filter_map(|item| legacy_kdbx_proposal(&item))
            .collect::<Vec<_>>();
        proposals.sort_by(|left, right| left.item_id.0.cmp(&right.item_id.0));
        let digest_material = serde_json::to_vec(
            &proposals
                .iter()
                .map(|proposal| {
                    (
                        &proposal.item_id,
                        proposal.expected_revision,
                        &proposal.proposed_kind,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|_| KeyLeaseError::Storage)?;
        let preview_digest = hex(&Sha256::digest(digest_material));
        Ok(MigrationPreview {
            migration_id: KDBX_RECLASSIFY_MIGRATION_ID.into(),
            version: 1,
            title: "Reclassify legacy Strongbox/KDBX items".into(),
            migration_type: "semantic".into(),
            preview_digest,
            proposals,
        })
    }

    pub fn get_entry_view(&self, actor: &ActorContext, id: &ItemId) -> Result<EntryView> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                "entry:read_fields",
                &resource,
                Value::Object(Default::default()),
            )?;
            let item = self.store.get_item(vault, id)?;
            let fields = item.fields.iter().map(field_view).collect();
            let view = EntryView {
                metadata: item.metadata(),
                template_version: item.template_version,
                project_id: item.project_id.clone(),
                tags: item.tags.clone(),
                sections: item.sections.clone(),
                fields,
                attachments: item.attachments.clone(),
                has_notes: item
                    .notes
                    .as_deref()
                    .is_some_and(|notes| !notes.trim().is_empty()),
            };
            self.audit_vault(
                actor,
                "entry:read_fields",
                &resource,
                "allow",
                "success",
                vec![],
            )?;
            Ok(view)
        })
    }

    pub fn reveal_field_by_id_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        field_id: &FieldId,
    ) -> Result<FieldValue> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}/{}", vault.vault_id.0, id.0, field_id.0);
            self.authorize_vault(
                vault,
                actor,
                "entry:read_secret",
                &resource,
                serde_json::json!({"field_id":field_id}),
            )?;
            let value = self
                .store
                .get_item(vault, id)?
                .fields
                .into_iter()
                .find(|field| field.id == *field_id)
                .map(|field| field.value)
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: field_id.0.clone(),
                })?;
            self.audit_vault(
                actor,
                "entry:read_secret",
                &resource,
                "allow",
                "success",
                vec!["field".into()],
            )?;
            Ok(value)
        })
    }

    /// Reveals an exact, bounded set of fields as one atomic disclosure.
    /// Every field resource is authorized before any value is returned.
    pub fn reveal_fields_by_id_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        field_ids: &[FieldId],
    ) -> Result<BTreeMap<String, FieldValue>> {
        if field_ids.is_empty() || field_ids.len() > 500 {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "batch reveal requires 1..=500 fields".into(),
            });
        }
        let mut unique = std::collections::HashSet::new();
        if field_ids.iter().any(|field_id| {
            field_id.0.is_empty()
                || field_id.0.len() > 128
                || field_id.0.chars().any(char::is_control)
                || !unique.insert(field_id.clone())
        }) {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "batch reveal field IDs must be unique and valid".into(),
            });
        }
        self.with_vault(|vault| {
            for field_id in field_ids {
                let resource = format!("kl://{}/{}/{}", vault.vault_id.0, id.0, field_id.0);
                self.authorize_vault(
                    vault,
                    actor,
                    "entry:read_secret",
                    &resource,
                    serde_json::json!({"field_id":field_id,"batch":true}),
                )?;
            }
            let item = self.store.get_item(vault, id)?;
            let by_id = item
                .fields
                .into_iter()
                .map(|field| (field.id.0, field.value))
                .collect::<HashMap<_, _>>();
            let mut values = BTreeMap::new();
            for field_id in field_ids {
                let value =
                    by_id
                        .get(&field_id.0)
                        .cloned()
                        .ok_or_else(|| KeyLeaseError::NotFound {
                            resource: field_id.0.clone(),
                        })?;
                values.insert(field_id.0.clone(), value);
            }
            let encoded = serde_json::to_vec(&values).map_err(|_| KeyLeaseError::Storage)?;
            if encoded.len() > 1024 * 1024 {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "batch reveal response exceeds 1 MiB".into(),
                });
            }
            self.audit_vault(
                actor,
                "entry:read_secret",
                &format!("kl://{}/{}", vault.vault_id.0, id.0),
                "allow",
                "success",
                vec![format!("fields:{}", values.len())],
            )?;
            Ok(values)
        })
    }

    pub fn list_projects_agent(&self, actor: &ActorContext) -> Result<Vec<VaultProject>> {
        self.with_vault(|vault| {
            self.ensure_agent_content_channel(actor)?;
            let projects = self.store.list_projects(vault)?;
            self.audit_vault(
                actor,
                "project:list",
                &vault.vault_id.0,
                "allow",
                "success",
                vec![],
            )?;
            Ok(projects)
        })
    }

    pub fn create_project_agent(
        &self,
        actor: &ActorContext,
        slug: &str,
        name: Option<&str>,
        idempotency_key: &str,
    ) -> Result<VaultProject> {
        self.with_vault(|vault| {
            self.ensure_agent_content_channel(actor)?;
            validate_idempotency_key(idempotency_key)?;
            let slug = normalize_project_slug(slug)?;
            let name = name.unwrap_or(&slug).to_owned();
            validate_project_name(&name)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"project:create",
                "actor":actor.agent_id,
                "slug":slug,
                "name":name,
            }))?;
            if let Some(replay) =
                self.store
                    .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return self.store.get_project(vault, &ProjectId(replay.item_id.0));
            }
            if self
                .store
                .list_projects(vault)?
                .iter()
                .any(|project| project.slug == slug)
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "project slug already exists".into(),
                });
            }
            let now = Utc::now();
            let project = VaultProject {
                id: ProjectId::new(),
                vault_id: vault.vault_id.clone(),
                slug,
                name,
                revision: 1,
                created_by: actor.agent_id.clone(),
                updated_by: actor.agent_id.clone(),
                created_at: now,
                updated_at: now,
                archived_at: None,
            };
            let audit = self.vault_audit_event(
                actor,
                "project:create",
                &project.id.0,
                "allow",
                "success",
                vec!["project".into()],
            );
            self.store.put_project(
                vault,
                &project,
                Some(0),
                MutationContext {
                    actor: &actor.agent_id.0,
                    idempotency_key,
                    request_material: &request_material,
                    audit_event: Some(&audit),
                },
            )?;
            Ok(project)
        })
    }

    pub fn search_content(
        &self,
        actor: &ActorContext,
        query: &str,
        kind: Option<&str>,
        tag: Option<&str>,
        project_slug: Option<&str>,
        reviewed_only: bool,
    ) -> Result<Vec<ContentSummary>> {
        self.with_vault(|vault| {
            self.ensure_agent_content_channel(actor)?;
            let owner = self.is_local_owner(&actor.agent_id)?;
            let projects = self.store.list_projects(vault)?;
            let project_by_id = projects
                .iter()
                .map(|project| (project.id.0.as_str(), project.slug.as_str()))
                .collect::<HashMap<_, _>>();
            let query = query.to_lowercase();
            let mut result = self
                .store
                .list_items(vault)?
                .into_iter()
                .filter(|item| is_agent_content_kind(&item.kind))
                .filter(|item| owner || item.agent_access != AgentAccess::None)
                .filter(|item| kind.is_none_or(|kind| item.kind == format!("core.{kind}")))
                .filter(|item| {
                    tag.is_none_or(|tag| {
                        item.tags
                            .iter()
                            .any(|candidate| candidate.eq_ignore_ascii_case(tag))
                    })
                })
                .filter(|item| {
                    project_slug.is_none_or(|slug| {
                        item.project_id
                            .as_ref()
                            .and_then(|id| project_by_id.get(id.0.as_str()))
                            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(slug))
                    })
                })
                .filter(|item| {
                    !reviewed_only
                        || item.content_metadata.as_ref().is_some_and(|metadata| {
                            metadata.review_state == ContentReviewState::HumanReviewed
                        })
                })
                .filter(|item| {
                    query.is_empty()
                        || item.title.to_lowercase().contains(&query)
                        || item
                            .tags
                            .iter()
                            .any(|tag| tag.to_lowercase().contains(&query))
                        || item
                            .notes
                            .as_deref()
                            .is_some_and(|body| body.to_lowercase().contains(&query))
                })
                .filter_map(|item| content_summary(&item, &projects))
                .take(100)
                .collect::<Vec<_>>();
            result.sort_by_key(|item| std::cmp::Reverse(item.updated_at));
            self.audit_vault(
                actor,
                "content:search",
                &vault.vault_id.0,
                "allow",
                "success",
                vec![],
            )?;
            Ok(result)
        })
    }

    pub fn get_content(&self, actor: &ActorContext, id: &ItemId) -> Result<ContentDocument> {
        self.with_vault(|vault| {
            self.ensure_agent_content_channel(actor)?;
            let item = self.store.get_item(vault, id)?;
            let owner = self.is_local_owner(&actor.agent_id)?;
            if !is_agent_content_kind(&item.kind)
                || (!owner && item.agent_access == AgentAccess::None)
            {
                return Err(KeyLeaseError::NotFound {
                    resource: id.0.clone(),
                });
            }
            let summary =
                content_summary(&item, &self.store.list_projects(vault)?).ok_or_else(|| {
                    KeyLeaseError::NotFound {
                        resource: id.0.clone(),
                    }
                })?;
            let body = item.notes.unwrap_or_default();
            self.audit_vault(actor, "content:read", &id.0, "allow", "success", vec![])?;
            Ok(ContentDocument { summary, body })
        })
    }

    pub fn create_content(
        &self,
        actor: &ActorContext,
        input: ContentCreateInput,
        idempotency_key: &str,
    ) -> Result<ContentDocument> {
        self.with_vault(|vault| {
            self.ensure_agent_content_channel(actor)?;
            validate_content(&input.title, &input.body, &input.tags)?;
            validate_idempotency_key(idempotency_key)?;
            if !is_agent_content_kind(&input.kind) {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "content kind must be core.prompt, core.runbook, or core.note".into(),
                });
            }
            let request_material = operation_material(&serde_json::json!({
                "operation":"content:create",
                "actor":actor.agent_id,
                "input":input,
            }))?;
            if let Some(replay) =
                self.store
                    .mutation_replay(vault, idempotency_key, &request_material)?
            {
                let item = self.store.get_item_at_revision(
                    vault,
                    &replay.item_id,
                    replay.result_revision,
                )?;
                return content_document(item, self.store.list_projects(vault)?);
            }
            let owner = self.is_local_owner(&actor.agent_id)?;
            let project_id = resolve_project_id(
                &self.store.list_projects(vault)?,
                input.project_slug.as_deref(),
            )?;
            let group_id = self.ensure_knowledge_group(vault)?;
            let now = Utc::now();
            let item = VaultItem {
                id: ItemId::new(),
                vault_id: vault.vault_id.clone(),
                group_id,
                kind: input.kind,
                title: input.title,
                sections: vec![],
                fields: vec![],
                urls: vec![],
                tags: normalize_tags(input.tags)?,
                favorite: input.favorite,
                attachments: vec![],
                notes: Some(input.body),
                template_version: 1,
                project_id,
                agent_access: if owner {
                    AgentAccess::None
                } else {
                    AgentAccess::ReadWrite
                },
                content_metadata: Some(ContentMetadata {
                    created_by: actor.agent_id.clone(),
                    last_modified_by: actor.agent_id.clone(),
                    review_state: if owner {
                        ContentReviewState::HumanReviewed
                    } else {
                        ContentReviewState::Unreviewed
                    },
                    reviewed_by: owner.then(|| "local-owner".into()),
                    reviewed_at: owner.then_some(now),
                }),
                schema_version: 2,
                revision: 1,
                created_at: now,
                updated_at: now,
                secret_changed_at: None,
                expires_at: None,
                rotation_interval_days: None,
                issuer: None,
                environment: None,
                owner: None,
                status: ItemStatus::Active,
                extensions: Default::default(),
            };
            let audit = self.vault_audit_event(
                actor,
                "content:create",
                &item.id.0,
                "allow",
                "success",
                vec!["content".into()],
            );
            self.store.put_item(
                vault,
                &item,
                Some(0),
                MutationContext {
                    actor: &actor.agent_id.0,
                    idempotency_key,
                    request_material: &request_material,
                    audit_event: Some(&audit),
                },
            )?;
            content_document(item, self.store.list_projects(vault)?)
        })
    }

    pub fn update_content(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        patch: ContentPatch,
        expected_revision: u64,
        idempotency_key: &str,
    ) -> Result<ContentDocument> {
        self.with_vault(|vault| {
            self.ensure_agent_content_channel(actor)?;
            validate_idempotency_key(idempotency_key)?;
            if patch.project_slug.is_some() && patch.clear_project {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "project_slug and clear_project are mutually exclusive".into(),
                });
            }
            if patch.title.is_none()
                && patch.body.is_none()
                && patch.tags.is_none()
                && patch.add_tags.is_empty()
                && patch.remove_tags.is_empty()
                && patch.project_slug.is_none()
                && !patch.clear_project
                && patch.favorite.is_none()
            {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "content update has no changes".into(),
                });
            }
            let request_material = operation_material(&serde_json::json!({
                "operation":"content:update",
                "actor":actor.agent_id,
                "item_id":id,
                "patch":patch,
                "expected_revision":expected_revision,
            }))?;
            if let Some(replay) =
                self.store
                    .mutation_replay(vault, idempotency_key, &request_material)?
            {
                let item = self.store.get_item_at_revision(
                    vault,
                    &replay.item_id,
                    replay.result_revision,
                )?;
                return content_document(item, self.store.list_projects(vault)?);
            }
            let mut item = self.store.get_item(vault, id)?;
            let owner = self.is_local_owner(&actor.agent_id)?;
            if !is_agent_content_kind(&item.kind)
                || (!owner && item.agent_access != AgentAccess::ReadWrite)
            {
                return Err(KeyLeaseError::Denied {
                    reason: "content item is not agent-writable".into(),
                });
            }
            if let Some(title) = patch.title {
                item.title = title;
            }
            if let Some(body) = patch.body {
                item.notes = Some(body);
            }
            if let Some(tags) = patch.tags {
                item.tags = normalize_tags(tags)?;
            }
            if let Some(favorite) = patch.favorite {
                item.favorite = favorite;
                item.extensions.remove("onepux.favorite_index");
            }
            for tag in patch.remove_tags {
                item.tags
                    .retain(|candidate| !candidate.eq_ignore_ascii_case(&tag));
            }
            item.tags.extend(patch.add_tags);
            item.tags = normalize_tags(item.tags)?;
            let projects = self.store.list_projects(vault)?;
            if patch.clear_project {
                item.project_id = None;
            } else if let Some(slug) = patch.project_slug.as_deref() {
                item.project_id = resolve_project_id(&projects, Some(slug))?;
            }
            validate_content(
                &item.title,
                item.notes.as_deref().unwrap_or_default(),
                &item.tags,
            )?;
            let now = Utc::now();
            let metadata = item
                .content_metadata
                .as_mut()
                .ok_or(KeyLeaseError::Crypto)?;
            metadata.last_modified_by = actor.agent_id.clone();
            metadata.review_state = if owner {
                ContentReviewState::HumanReviewed
            } else {
                ContentReviewState::Unreviewed
            };
            metadata.reviewed_by = owner.then(|| "local-owner".into());
            metadata.reviewed_at = owner.then_some(now);
            item.schema_version = 2;
            item.revision = expected_revision + 1;
            item.updated_at = now;
            let audit = self.vault_audit_event(
                actor,
                "content:update",
                &item.id.0,
                "allow",
                "success",
                vec!["content".into()],
            );
            self.store.put_item(
                vault,
                &item,
                Some(expected_revision),
                MutationContext {
                    actor: &actor.agent_id.0,
                    idempotency_key,
                    request_material: &request_material,
                    audit_event: Some(&audit),
                },
            )?;
            content_document(item, projects)
        })
    }

    pub fn set_content_access(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        access: AgentAccess,
        expected_revision: u64,
        idempotency_key: &str,
    ) -> Result<ContentDocument> {
        self.with_vault(|vault| {
            if !self.is_local_owner(&actor.agent_id)? {
                return Err(KeyLeaseError::Denied {
                    reason: "only the local owner may change agent access".into(),
                });
            }
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"content:set_access",
                "actor":actor.agent_id,
                "item_id":id,
                "access":access,
                "expected_revision":expected_revision,
            }))?;
            if let Some(replay) =
                self.store
                    .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return content_document(
                    self.store.get_item_at_revision(
                        vault,
                        &replay.item_id,
                        replay.result_revision,
                    )?,
                    self.store.list_projects(vault)?,
                );
            }
            let mut item = self.store.get_item(vault, id)?;
            if !is_agent_content_kind(&item.kind) {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "agent access is only valid for Prompt, Runbook, and Note".into(),
                });
            }
            item.agent_access = access;
            item.revision = expected_revision + 1;
            item.schema_version = 2;
            item.updated_at = Utc::now();
            let audit = self.vault_audit_event(
                actor,
                "content:set_access",
                &item.id.0,
                "allow",
                "success",
                vec!["agent_access".into()],
            );
            self.store.put_item(
                vault,
                &item,
                Some(expected_revision),
                MutationContext {
                    actor: &actor.agent_id.0,
                    idempotency_key,
                    request_material: &request_material,
                    audit_event: Some(&audit),
                },
            )?;
            content_document(item, self.store.list_projects(vault)?)
        })
    }

    pub fn review_content(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        expected_revision: u64,
        idempotency_key: &str,
    ) -> Result<ContentDocument> {
        self.with_vault(|vault| {
            if !self.is_local_owner(&actor.agent_id)? {
                return Err(KeyLeaseError::Denied {
                    reason: "only the local owner may review content".into(),
                });
            }
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"content:review",
                "actor":actor.agent_id,
                "item_id":id,
                "expected_revision":expected_revision,
            }))?;
            if let Some(replay) =
                self.store
                    .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return content_document(
                    self.store.get_item_at_revision(
                        vault,
                        &replay.item_id,
                        replay.result_revision,
                    )?,
                    self.store.list_projects(vault)?,
                );
            }
            let mut item = self.store.get_item(vault, id)?;
            if !is_agent_content_kind(&item.kind) {
                return Err(KeyLeaseError::InvalidRequest {
                    reason: "only Prompt, Runbook, and Note can be reviewed".into(),
                });
            }
            let now = Utc::now();
            let metadata = item
                .content_metadata
                .as_mut()
                .ok_or(KeyLeaseError::Crypto)?;
            metadata.review_state = ContentReviewState::HumanReviewed;
            metadata.reviewed_by = Some("local-owner".into());
            metadata.reviewed_at = Some(now);
            item.revision = expected_revision + 1;
            item.schema_version = 2;
            item.updated_at = now;
            let audit = self.vault_audit_event(
                actor,
                "content:review",
                &item.id.0,
                "allow",
                "success",
                vec!["review_state".into()],
            );
            self.store.put_item(
                vault,
                &item,
                Some(expected_revision),
                MutationContext {
                    actor: &actor.agent_id.0,
                    idempotency_key,
                    request_material: &request_material,
                    audit_event: Some(&audit),
                },
            )?;
            content_document(item, self.store.list_projects(vault)?)
        })
    }

    pub(crate) fn ensure_agent_content_channel(&self, actor: &ActorContext) -> Result<()> {
        if !self.is_local_owner(&actor.agent_id)? && self.store.kill_switch_enabled()? {
            return Err(KeyLeaseError::Denied {
                reason: "global kill switch is active".into(),
            });
        }
        Ok(())
    }

    pub(crate) fn ensure_knowledge_group(&self, vault: &UnlockedVault) -> Result<GroupId> {
        if let Some(group) = self
            .store
            .list_groups(vault)?
            .into_iter()
            .find(|group| group.purpose == GroupPurpose::Knowledge)
        {
            return Ok(group.id);
        }
        let now = Utc::now();
        let group = VaultGroup {
            id: GroupId::new(),
            vault_id: vault.vault_id.clone(),
            parent_id: None,
            name: "Knowledge".into(),
            purpose: GroupPurpose::Knowledge,
            sort_order: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        self.store.put_group(vault, &group, Some(0), None)?;
        Ok(group.id)
    }
    pub fn reveal_field_for_human(&self, id: &ItemId, key: &str) -> Result<String> {
        self.with_vault(|vault| {
            let item = self.store.get_item(vault, id)?;
            if key == "notes" {
                return item
                    .notes
                    .filter(|notes| !notes.trim().is_empty())
                    .ok_or_else(|| KeyLeaseError::NotFound {
                        resource: format!("{}/notes", id.0),
                    });
            }
            item.fields
                .into_iter()
                .find(|field| field.key == key)
                .map(|field| field_value_string(&field.value))
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/{}", id.0, key),
                })
        })
    }
    pub fn reveal_field_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        key: &str,
    ) -> Result<String> {
        if key.is_empty()
            || key.len() > 128
            || key.chars().any(char::is_control)
            || matches!(key, "otp")
        {
            return Err(KeyLeaseError::InvalidRequest {
                reason: "invalid reveal field".into(),
            });
        }
        self.with_vault(|vault| {
            let action = if key == "username" {
                "entry:read_username"
            } else {
                "entry:read_secret"
            };
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                action,
                &resource,
                serde_json::json!({"field":key}),
            )?;
            let item = self.store.get_item(vault, id)?;
            let value = if key == "notes" {
                item.notes.filter(|notes| !notes.trim().is_empty())
            } else {
                item.fields
                    .into_iter()
                    .find(|field| field.key == key)
                    .map(|field| field_value_string(&field.value))
            }
            .ok_or_else(|| KeyLeaseError::NotFound {
                resource: format!("{}/{}", id.0, key),
            })?;
            self.audit_vault(
                actor,
                action,
                &resource,
                "allow",
                "success",
                vec![key.into()],
            )?;
            Ok(value)
        })
    }
    pub fn totp_for_human(&self, id: &ItemId) -> Result<(String, u64)> {
        self.with_vault(|vault| {
            let item = self.store.get_item(vault, id)?;
            let config = item
                .fields
                .into_iter()
                .find(|field| field.key == "otp")
                .and_then(|field| match field.value {
                    FieldValue::Totp(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/otp", id.0),
                })?;
            current_totp(&config)
        })
    }
    pub fn totp_authorized(&self, actor: &ActorContext, id: &ItemId) -> Result<(String, u64)> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                "entry:read_secret",
                &resource,
                serde_json::json!({"field":"otp","representation":"current_code"}),
            )?;
            let item = self.store.get_item(vault, id)?;
            let config = item
                .fields
                .into_iter()
                .find(|field| field.key == "otp")
                .and_then(|field| match field.value {
                    FieldValue::Totp(value) => Some(value),
                    _ => None,
                })
                .ok_or_else(|| KeyLeaseError::NotFound {
                    resource: format!("{}/otp", id.0),
                })?;
            let result = current_totp(&config)?;
            self.audit_vault(
                actor,
                "entry:read_secret",
                &resource,
                "allow",
                "success",
                vec!["otp".into()],
            )?;
            Ok(result)
        })
    }
    pub fn entry_history_for_human(&self, id: &ItemId) -> Result<Vec<ItemMetadata>> {
        self.with_vault(|vault| {
            self.store
                .item_history(vault, id)
                .map(|items| items.into_iter().map(|item| item.metadata()).collect())
        })
    }
    pub fn entry_history_authorized(
        &self,
        actor: &ActorContext,
        id: &ItemId,
    ) -> Result<Vec<ItemMetadata>> {
        self.with_vault(|vault| {
            let resource = format!("kl://{}/{}", vault.vault_id.0, id.0);
            self.authorize_vault(
                vault,
                actor,
                "entry:read_metadata",
                &resource,
                serde_json::json!({"view":"history"}),
            )?;
            let history = self
                .store
                .item_history(vault, id)?
                .into_iter()
                .map(|item| {
                    let mut metadata = item.metadata();
                    metadata.username = None;
                    metadata
                })
                .collect();
            self.audit_vault(
                actor,
                "entry:read_metadata",
                &resource,
                "allow",
                "success",
                vec!["history".into()],
            )?;
            Ok(history)
        })
    }
    pub fn delete_entry(
        &self,
        actor: &ActorContext,
        id: &ItemId,
        expected_revision: u64,
        idempotency_key: &str,
        dry_run: bool,
    ) -> Result<()> {
        self.with_vault(|vault| {
            validate_idempotency_key(idempotency_key)?;
            let request_material = operation_material(&serde_json::json!({
                "operation":"entry:delete",
                "actor":actor.agent_id,
                "item_id":id,
                "expected_revision":expected_revision,
            }))?;
            self.authorize_vault(
                vault,
                actor,
                "entry:delete",
                &format!("kl://{}/{}", vault.vault_id.0, id.0),
                serde_json::json!({"expected_revision":expected_revision}),
            )?;
            if !dry_run
                && let Some(replay) =
                    self.store
                        .mutation_replay(vault, idempotency_key, &request_material)?
            {
                return if replay.item_id == *id {
                    Ok(())
                } else {
                    Err(KeyLeaseError::IdempotencyConflict)
                };
            }
            let item = self.store.get_item(vault, id)?;
            refuse_shared_copy(&item)?;
            if item.revision != expected_revision {
                return Err(KeyLeaseError::RevisionConflict {
                    expected: expected_revision,
                    actual: item.revision,
                    retryable: false,
                });
            }
            if !dry_run {
                let audit = self.vault_audit_event(
                    actor,
                    "entry:delete",
                    &id.0,
                    "allow",
                    "success",
                    vec![],
                );
                self.store.delete_item(
                    vault,
                    id,
                    expected_revision,
                    MutationContext {
                        actor: &actor.agent_id.0,
                        idempotency_key,
                        request_material: &request_material,
                        audit_event: Some(&audit),
                    },
                )?;
            } else {
                self.audit_vault(actor, "entry:delete", &id.0, "allow", "dry_run", vec![])?;
            }
            Ok(())
        })
    }
}
