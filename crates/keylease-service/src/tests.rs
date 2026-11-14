use super::*;

#[test]
fn canonical_template_roles_cannot_be_downgraded_by_a_client() {
    let mut fields = vec![ItemField {
        id: FieldId::new(),
        key: "cc number".into(),
        label: "Card Number".into(),
        value: FieldValue::Text("4111111111111111".into()),
        sensitivity: Sensitivity::PublicMetadata,
        protected: false,
        semantic_role: None,
    }];
    canonicalize_template_fields("core.credit_card", &mut fields);
    let field = &fields[0];
    assert_eq!(field.semantic_role.as_deref(), Some("card_number"));
    assert_eq!(field.sensitivity, Sensitivity::HighlySensitive);
    assert!(field.protected);
    assert!(matches!(field.value, FieldValue::Concealed(_)));
}

#[test]
fn semantic_migration_previews_applies_and_rolls_back_atomically() {
    let (_dir, service, actor) = service();
    let group = service.create_group("Imported", None).unwrap();
    let created = service
        .create_entry(
            &actor,
            NewEntryInput {
                favorite: false,
                group_id: group.id,
                kind: "core.login".into(),
                title: "VISA test".into(),
                project_slug: None,
                username: None,
                password: None,
                url: None,
                notes: None,
                custom_fields: vec![
                    ItemField {
                        id: FieldId::new(),
                        key: "Number".into(),
                        label: "Number".into(),
                        value: FieldValue::Concealed("4111111111111111".into()),
                        sensitivity: Sensitivity::HighlySensitive,
                        protected: true,
                        semantic_role: None,
                    },
                    ItemField {
                        id: FieldId::new(),
                        key: "Expiration Date".into(),
                        label: "Expiration Date".into(),
                        value: FieldValue::Text("09/2029".into()),
                        sensitivity: Sensitivity::PrivateMetadata,
                        protected: false,
                        semantic_role: None,
                    },
                ],
                sections: vec![],
                totp: None,
                totp_uri: None,
                environment: None,
                personal: false,
            },
            "legacy-card",
            false,
        )
        .unwrap();
    let (owner_id, owner_token) = service.register_desktop_client().unwrap();
    let owner = service
        .authenticate(&owner_id, &owner_token, "migration-owner")
        .unwrap();
    let preview = service
        .preview_migration(&owner, KDBX_RECLASSIFY_MIGRATION_ID)
        .unwrap();
    assert_eq!(preview.proposals.len(), 1);
    assert_eq!(preview.proposals[0].item_id, created.id);
    assert_eq!(preview.proposals[0].proposed_kind, "core.credit_card");
    assert!(matches!(
        service.apply_migration(&owner, KDBX_RECLASSIFY_MIGRATION_ID, "stale"),
        Err(KeyLeaseError::RevisionConflict {
            retryable: true,
            ..
        })
    ));
    let applied = service
        .apply_migration(
            &owner,
            KDBX_RECLASSIFY_MIGRATION_ID,
            &preview.preview_digest,
        )
        .unwrap();
    assert_eq!(applied.item_count, 1);
    assert!(
        service
            .preview_migration(&owner, KDBX_RECLASSIFY_MIGRATION_ID)
            .unwrap()
            .proposals
            .is_empty()
    );
    let rolled_back = service
        .rollback_migration(&owner, KDBX_RECLASSIFY_MIGRATION_ID)
        .unwrap();
    assert_eq!(rolled_back.item_count, 1);
    assert_eq!(
        service
            .preview_migration(&owner, KDBX_RECLASSIFY_MIGRATION_ID)
            .unwrap()
            .proposals
            .len(),
        1
    );
}

fn service() -> (tempfile::TempDir, KeyLeaseService, ActorContext) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    let vault = service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_client("test").unwrap();
    let actor = service
        .authenticate(&agent, &token, "session-test")
        .unwrap();
    for (action, resource) in [
        ("entry:create", format!("kl://{}/group", vault.0)),
        ("entry:search", format!("kl://{}", vault.0)),
        ("entry:update_standard_fields", format!("kl://{}", vault.0)),
        ("entry:update_protected_fields", format!("kl://{}", vault.0)),
        ("group:create", format!("kl://{}", vault.0)),
        ("group:update", format!("kl://{}", vault.0)),
        ("group:delete", format!("kl://{}", vault.0)),
        ("connection:add", format!("kl://{}", vault.0)),
    ] {
        service
            .add_grant(PolicyRule {
                id: action.into(),
                version: 1,
                effect: PolicyEffect::Allow,
                agent_id: Some(agent.clone()),
                connection_id: None,
                resource_prefix: resource,
                actions: vec![action.into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: None,
                max_lease_ttl_seconds: 600,
                max_uses: 10,
                budget: Default::default(),
            })
            .unwrap();
    }
    (dir, service, actor)
}

#[test]
fn desktop_agent_handoff_is_scoped_repeatable_and_cleared_on_lock() {
    let (_dir, service, ordinary_actor) = service();
    let group = service.create_group("Work", None).unwrap();
    let (owner_id, owner_token) = service.register_desktop_client().unwrap();
    let owner = service
        .authenticate(&owner_id, &owner_token, "desktop-handoff")
        .unwrap();
    let input = AgentNewItemHandoffInput {
        protocol_version: AGENT_NEW_ITEM_PROTOCOL_VERSION,
        expected_vault_id: group.vault_id.clone(),
        recipe_id: "ssh_topology".into(),
        kind: "core.ssh_server".into(),
        group_id: Some(group.id.clone()),
        project_slug: None,
        tags: vec![],
        agent_access: AgentAccess::ReadWrite,
        source_path: Some(" ~/.ssh/config ".into()),
        context: Some(" One bastion and one application server ".into()),
    };
    assert!(matches!(
        service.create_agent_new_item_handoff_authorized(&ordinary_actor, input.clone()),
        Err(KeyLeaseError::Denied { .. })
    ));

    let receipt = service
        .create_agent_new_item_handoff_authorized(&owner, input)
        .unwrap();
    assert!(receipt.command.ends_with(&receipt.handoff_id));
    let guide = service
        .get_agent_new_item_handoff_authorized(&owner, &receipt.handoff_id)
        .unwrap();
    assert_eq!(guide.vault_id, group.vault_id);
    assert_eq!(guide.group_id.as_ref(), Some(&group.id));
    assert_eq!(guide.group_name.as_deref(), Some("Work"));
    assert_eq!(guide.source_path.as_deref(), Some("~/.ssh/config"));
    assert_eq!(
        guide.context.as_deref(),
        Some("One bastion and one application server")
    );
    assert!(guide.workflow.iter().any(|step| step.contains("--dry-run")));
    assert!(
        guide
            .kind_requirements
            .iter()
            .any(|rule| rule.contains("ssh_connect_via"))
    );
    assert_eq!(
        service
            .get_agent_new_item_handoff_authorized(&owner, &receipt.handoff_id)
            .unwrap(),
        guide
    );

    service.lock().unwrap();
    service.unlock(b"password", Duration::hours(1)).unwrap();
    assert!(matches!(
        service.get_agent_new_item_handoff_authorized(&owner, &receipt.handoff_id),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
}

#[test]
fn agent_handoff_builds_content_guide_and_expires_without_sliding() {
    let (_dir, service, _) = service();
    let vault_id = VaultId(
        service.status().unwrap()["vault_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    let (owner_id, owner_token) = service.register_desktop_client().unwrap();
    let owner = service
        .authenticate(&owner_id, &owner_token, "desktop-content-handoff")
        .unwrap();
    let receipt = service
        .create_agent_new_item_handoff_authorized(
            &owner,
            AgentNewItemHandoffInput {
                protocol_version: AGENT_NEW_ITEM_PROTOCOL_VERSION,
                expected_vault_id: vault_id,
                recipe_id: "prompt".into(),
                kind: "core.prompt".into(),
                group_id: None,
                project_slug: None,
                tags: vec!["agent".into(), "reusable".into()],
                agent_access: AgentAccess::ReadWrite,
                source_path: None,
                context: Some("Turn this task into a reusable prompt".into()),
            },
        )
        .unwrap();
    let guide = service
        .get_agent_new_item_handoff_authorized(&owner, &receipt.handoff_id)
        .unwrap();
    assert!(
        guide
            .workflow
            .iter()
            .any(|step| step.contains("content create --type prompt"))
    );
    assert!(
        guide
            .workflow
            .iter()
            .all(|step| !step.contains("--dry-run"))
    );

    service
        .agent_handoffs
        .lock()
        .unwrap()
        .get_mut(&receipt.handoff_id)
        .unwrap()
        .expires_at = Instant::now() - StdDuration::from_secs(1);
    assert!(matches!(
        service.get_agent_new_item_handoff_authorized(&owner, &receipt.handoff_id),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
}

#[test]
fn agent_handoff_rejects_wrong_vault_missing_source_and_large_context() {
    let (_dir, service, _) = service();
    let group = service.create_group("Work", None).unwrap();
    let (owner_id, owner_token) = service.register_desktop_client().unwrap();
    let owner = service
        .authenticate(&owner_id, &owner_token, "desktop-invalid-handoff")
        .unwrap();
    let base = AgentNewItemHandoffInput {
        protocol_version: AGENT_NEW_ITEM_PROTOCOL_VERSION,
        expected_vault_id: group.vault_id,
        recipe_id: "dotenv".into(),
        kind: "core.environment".into(),
        group_id: Some(group.id),
        project_slug: None,
        tags: vec![],
        agent_access: AgentAccess::ReadWrite,
        source_path: None,
        context: None,
    };
    let mut wrong_vault = base.clone();
    wrong_vault.expected_vault_id = VaultId("vault_other".into());
    assert!(matches!(
        service.create_agent_new_item_handoff_authorized(&owner, wrong_vault),
        Err(KeyLeaseError::Denied { .. })
    ));
    assert!(matches!(
        service.create_agent_new_item_handoff_authorized(&owner, base.clone()),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
    let mut large = base;
    large.recipe_id = "describe".into();
    large.context = Some("x".repeat(MAX_AGENT_CONTEXT_BYTES + 1));
    assert!(matches!(
        service.create_agent_new_item_handoff_authorized(&owner, large),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
}

#[test]
fn agent_group_create_is_idempotent_and_audited() {
    let (_dir, service, actor) = service();
    let created = service
        .create_group_authorized(&actor, "Development", None, "group-task", false)
        .unwrap();
    let replay = service
        .create_group_authorized(&actor, "Development", None, "group-task", false)
        .unwrap();
    assert_eq!(created.id, replay.id);
    assert_eq!(service.list_groups().unwrap().len(), 1);
    assert!(matches!(
        service.create_group_authorized(&actor, "Different", None, "group-task", false),
        Err(KeyLeaseError::IdempotencyConflict)
    ));
    let updated = service
        .update_group_authorized(&actor, &created.id, "Engineering", 1, "group-update", false)
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(
        service
            .update_group_authorized(&actor, &created.id, "Engineering", 1, "group-update", false,)
            .unwrap(),
        updated
    );
    service
        .delete_group_authorized(&actor, &created.id, 2, "group-delete", false)
        .unwrap();
    service
        .delete_group_authorized(&actor, &created.id, 2, "group-delete", false)
        .unwrap();
    assert!(service.list_groups().unwrap().is_empty());
    assert!(
        service
            .audit_query(10)
            .unwrap()
            .iter()
            .filter(|event| event.action.starts_with("group:"))
            .all(|event| event.outcome == "success")
    );
}
#[test]
fn agent_write_search_and_revision_are_policy_enforced() {
    let (_dir, service, actor) = service();
    let group = service.create_group("Development", None).unwrap();
    let input = NewEntryInput {
        favorite: false,
        group_id: group.id,
        kind: "core.login".into(),
        title: "GitHub".into(),
        project_slug: None,
        username: Some("bot".into()),
        password: Some("new-secret".into()),
        url: Some("https://github.com".into()),
        notes: Some("Recovery instructions".into()),
        custom_fields: vec![],
        sections: vec![],
        totp: None,
        totp_uri: None,
        environment: None,
        personal: false,
    };
    let item = service
        .create_entry(&actor, input.clone(), "task-create", false)
        .unwrap();
    assert!(!serde_json::to_string(&item).unwrap().contains("new-secret"));
    assert!(item.has_password);
    assert!(item.has_notes);
    assert!(
        !serde_json::to_string(&item)
            .unwrap()
            .contains("Recovery instructions")
    );
    assert!(matches!(
        service.reveal_field_authorized(&actor, &item.id, "password"),
        Err(KeyLeaseError::Denied { .. })
    ));
    for action in [
        "entry:read_metadata",
        "entry:read_username",
        "entry:read_secret",
    ] {
        service
            .add_grant(PolicyRule {
                id: format!("desktop-{action}"),
                version: 1,
                effect: PolicyEffect::Allow,
                agent_id: Some(actor.agent_id.clone()),
                connection_id: None,
                resource_prefix: format!("kl://{}", group.vault_id.0),
                actions: vec![action.into()],
                argument_equals: Default::default(),
                not_before: None,
                expires_at: None,
                max_lease_ttl_seconds: 600,
                max_uses: 10,
                budget: Default::default(),
            })
            .unwrap();
    }
    assert_eq!(
        service
            .reveal_field_authorized(&actor, &item.id, "username")
            .unwrap(),
        "bot"
    );
    assert_eq!(
        service
            .reveal_field_authorized(&actor, &item.id, "password")
            .unwrap(),
        "new-secret"
    );
    assert_eq!(
        service
            .reveal_field_authorized(&actor, &item.id, "notes")
            .unwrap(),
        "Recovery instructions"
    );
    assert!(
        service
            .entry_history_authorized(&actor, &item.id)
            .unwrap()
            .is_empty()
    );
    assert!(
        !serde_json::to_string(&service.audit_query(20).unwrap())
            .unwrap()
            .contains("new-secret")
    );
    assert_eq!(service.search_entries(&actor, "github").unwrap().len(), 1);
    let error = service
        .update_entry(
            &actor,
            &item.id,
            EntryPatch {
                title: Some("Changed".into()),
                ..Default::default()
            },
            0,
            "task-update",
            false,
        )
        .unwrap_err();
    assert!(matches!(error, KeyLeaseError::RevisionConflict { .. }));
    let update_patch = EntryPatch {
        title: Some("Changed".into()),
        field_updates: vec![ItemField {
            id: FieldId::new(),
            key: "environment".into(),
            label: "Environment".into(),
            value: FieldValue::Text("production".into()),
            sensitivity: Sensitivity::PrivateMetadata,
            protected: false,
            semantic_role: Some("environment".into()),
        }],
        ..Default::default()
    };
    let updated = service
        .update_entry(
            &actor,
            &item.id,
            update_patch.clone(),
            1,
            "task-update-success",
            false,
        )
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(
        service
            .reveal_field_authorized(&actor, &item.id, "environment")
            .unwrap(),
        "production"
    );
    assert_eq!(
        service
            .reveal_field_authorized(&actor, &item.id, "password")
            .unwrap(),
        "new-secret"
    );
    let repeated_update = service
        .update_entry(
            &actor,
            &item.id,
            update_patch,
            1,
            "task-update-success",
            false,
        )
        .unwrap();
    assert_eq!(repeated_update, updated);
    let repeated_create = service
        .create_entry(&actor, input, "task-create", false)
        .unwrap();
    assert_eq!(repeated_create.id, item.id);
    assert_eq!(repeated_create.revision, 1);
    let history = service.entry_history_for_human(&item.id).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].revision, 1);
    let authorized_history = service.entry_history_authorized(&actor, &item.id).unwrap();
    assert_eq!(authorized_history.len(), 1);
    assert_eq!(authorized_history[0].username, None);
    let destination = service.create_group("Other", None).unwrap();
    assert!(matches!(
        service.update_entry(
            &actor,
            &item.id,
            EntryPatch {
                title: Some("Mixed".into()),
                group_id: Some(destination.id),
                ..Default::default()
            },
            2,
            "mixed-capability-update",
            false,
        ),
        Err(KeyLeaseError::Denied { .. })
    ));
    assert_eq!(service.entry_history_for_human(&item.id).unwrap().len(), 1);
    service
        .add_grant(PolicyRule {
            id: "entry-delete".into(),
            version: 1,
            effect: PolicyEffect::Allow,
            agent_id: Some(actor.agent_id.clone()),
            connection_id: None,
            resource_prefix: format!("kl://{}", group.vault_id.0),
            actions: vec!["entry:delete".into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 60,
            max_uses: 1,
            budget: Default::default(),
        })
        .unwrap();
    service
        .delete_entry(&actor, &item.id, 2, "task-delete", false)
        .unwrap();
    service
        .delete_entry(&actor, &item.id, 2, "task-delete", false)
        .unwrap();
    let events = service.audit_query(10).unwrap();
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("new-secret")
    );
}

#[test]
fn structured_entries_keep_project_identity_through_search_and_reassignment() {
    let (_dir, service, actor) = service();
    let alpha = service
        .create_project_agent(&actor, "alpha", Some("Alpha"), "project-alpha")
        .unwrap();
    let beta = service
        .create_project_agent(&actor, "beta", Some("Beta"), "project-beta")
        .unwrap();
    let group = service.create_group("Servers", None).unwrap();
    let item = service
        .create_entry(
            &actor,
            NewEntryInput {
                group_id: group.id,
                kind: "core.server".into(),
                title: "Build host".into(),
                project_slug: Some("alpha".into()),
                favorite: false,
                username: None,
                password: None,
                url: None,
                notes: None,
                custom_fields: vec![],
                sections: vec![],
                totp: None,
                totp_uri: None,
                environment: None,
                personal: false,
            },
            "create-project-entry",
            false,
        )
        .unwrap();
    assert_eq!(item.project_id, Some(alpha.id));
    assert_eq!(
        service
            .search_entries_scoped(&actor, "Build", Some("alpha"), false)
            .unwrap()
            .len(),
        1
    );
    assert!(
        service
            .search_entries_scoped(&actor, "Build", Some("beta"), false)
            .unwrap()
            .is_empty()
    );
    assert!(
        service
            .search_entries_scoped(&actor, "Build", None, true)
            .unwrap()
            .is_empty()
    );

    let moved = service
        .update_entry(
            &actor,
            &item.id,
            EntryPatch {
                project_slug: Some("beta".into()),
                ..Default::default()
            },
            item.revision,
            "move-project-entry",
            false,
        )
        .unwrap();
    assert_eq!(moved.project_id, Some(beta.id));
    assert!(
        service
            .search_entries_scoped(&actor, "Build", Some("alpha"), false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        service
            .search_entries_scoped(&actor, "Build", Some("beta"), false)
            .unwrap()
            .len(),
        1
    );

    let cleared = service
        .update_entry(
            &actor,
            &item.id,
            EntryPatch {
                clear_project: true,
                ..Default::default()
            },
            moved.revision,
            "clear-project-entry",
            false,
        )
        .unwrap();
    assert_eq!(cleared.project_id, None);
    assert_eq!(
        service
            .search_entries_scoped(&actor, "Build", None, true)
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn unknown_agent_has_no_vault_access() {
    let (_dir, service, _) = service();
    let actor = ActorContext {
        agent_id: AgentId("agent_unknown".into()),
        workload_id: None,
        human_principal: None,
        purpose: None,
        on_behalf_of: None,
        client_session_id: "s".into(),
    };
    assert!(matches!(
        service.search_entries(&actor, ""),
        Err(KeyLeaseError::Denied { .. })
    ));
}
#[test]
fn locking_revokes_session_scoped_grants() {
    let (_dir, service, actor) = service();
    assert!(service.search_entries(&actor, "").is_ok());
    service.lock().unwrap();
    service.unlock(b"password", Duration::hours(1)).unwrap();
    assert!(matches!(
        service.search_entries(&actor, ""),
        Err(KeyLeaseError::Denied { .. })
    ));
}
#[test]
fn lease_concurrency_slots_are_enforced_and_released() {
    let (_dir, service, _) = service();
    let lease = AccessLease {
        id: LeaseId::new(),
        token: "unused".into(),
        request_digest_hex: "unused".into(),
        policy_version: 1,
        action: "fake.resource.read".into(),
        resource: "fake:resource/1".into(),
        audience: "fake".into(),
        expires_at: Utc::now() + Duration::minutes(1),
        max_uses: 2,
        remaining_uses: 2,
        budget: DataBudget {
            max_concurrent: Some(1),
            ..Default::default()
        },
        approval_id: None,
        session_id: "session".into(),
        revoked: false,
    };
    let first = service.acquire_execution_slot(&lease).unwrap();
    assert!(matches!(
        service.acquire_execution_slot(&lease),
        Err(KeyLeaseError::Denied { .. })
    ));
    drop(first);
    assert!(service.acquire_execution_slot(&lease).is_ok());
}
#[test]
fn repeated_client_authentication_failures_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("auth.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_client("limited").unwrap();
    for _ in 0..AUTH_FAILURE_LIMIT {
        assert!(service.authenticate(&agent, "wrong", "session").is_err());
    }
    let error = service.authenticate(&agent, &token, "session").unwrap_err();
    assert!(matches!(
        error,
        KeyLeaseError::Denied { reason } if reason.contains("rate limit")
    ));
}
#[test]
fn totp_uri_accepts_short_secrets_with_structural_validation() {
    for (algorithm, expected) in [
        ("SHA1", TotpAlgorithm::Sha1),
        ("SHA256", TotpAlgorithm::Sha256),
        ("SHA512", TotpAlgorithm::Sha512),
    ] {
        let source = format!(
            "otpauth://totp/Example:test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm={algorithm}&digits=8&period=45"
        );
        let mut uri = Some(format!(" \n{source}\r\n "));
        let mut config = None;
        normalize_totp(&mut config, &mut uri).unwrap();
        let config = config.unwrap();
        assert_eq!(config.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(config.issuer.as_deref(), Some("Example"));
        assert_eq!(config.account.as_deref(), Some("test"));
        assert_eq!(config.algorithm, expected);
        assert_eq!(config.digits, 8);
        assert_eq!(config.period, 45);
        assert_eq!(
            config.source_representation.as_deref(),
            Some(source.as_str())
        );
        assert_eq!(current_totp(&config).unwrap().0.len(), 8);
        assert!(uri.is_none());
    }
}

#[test]
fn totp_uri_rejects_malformed_inputs_without_panicking() {
    for source in [
        "not a URI",
        "otpauth:/test?secret=JBSWY3DPEHPK3PXP",
        "https://totp/test?secret=JBSWY3DPEHPK3PXP",
        "otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/test",
        "otpauth://totp/test?secret=",
        "otpauth://totp/test?secret=INVALID!",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=5",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=9",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        "otpauth://totp/Example:test?secret=JBSWY3DPEHPK3PXP&issuer=Other",
        "otpauth://totp/Example:test:extra?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Example:Other",
    ] {
        let error = normalize_totp(&mut None, &mut Some(source.into())).unwrap_err();
        assert!(matches!(error, KeyLeaseError::InvalidRequest { .. }));
        assert!(!format!("{error:?}").contains("JBSWY3DPEHPK3PXP"));
    }
}

#[test]
fn totp_typed_config_validation_matches_generation() {
    let valid = TotpConfig {
        secret_base32: "JBSWY3DPEHPK3PXP".into(),
        issuer: None,
        account: None,
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        source_representation: None,
    };
    normalize_totp(&mut Some(valid.clone()), &mut None).unwrap();
    for invalid in [
        TotpConfig {
            secret_base32: String::new(),
            ..valid.clone()
        },
        TotpConfig {
            secret_base32: "INVALID!".into(),
            ..valid.clone()
        },
        TotpConfig {
            digits: 5,
            ..valid.clone()
        },
        TotpConfig {
            period: 0,
            ..valid.clone()
        },
    ] {
        assert!(normalize_totp(&mut Some(invalid.clone()), &mut None).is_err());
        assert!(current_totp(&invalid).is_err());
    }
    assert!(normalize_totp(&mut Some(valid), &mut Some("otpauth://totp/test".into())).is_err());
}

#[test]
fn totp_short_uri_survives_create_update_and_failed_save() {
    let (_dir, service, _) = service();
    let group = service.create_group("TOTP tests", None).unwrap();
    let (owner_id, token) = service.register_desktop_client().unwrap();
    service.lock().unwrap();
    service
        .unlock_for_client(&owner_id, b"password", Duration::hours(1))
        .unwrap();
    let owner = service
        .authenticate(&owner_id, &token, "totp-test")
        .unwrap();
    let source = "otpauth://totp/Example:test?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let input = NewEntryInput {
        favorite: false,
        group_id: group.id,
        kind: "core.login".into(),
        title: "TOTP fixture".into(),
        project_slug: None,
        username: None,
        password: None,
        url: None,
        notes: None,
        custom_fields: vec![],
        sections: vec![],
        totp: None,
        totp_uri: Some(source.into()),
        environment: None,
        personal: false,
    };
    let created = service
        .create_entry(&owner, input, "totp-create", false)
        .unwrap();
    assert!(created.has_totp);
    let stored_totp = || {
        service
            .with_vault(|vault| {
                Ok(service
                    .store
                    .get_item(vault, &created.id)?
                    .fields
                    .into_iter()
                    .find_map(|field| match field.value {
                        FieldValue::Totp(config) if field.key == "otp" => Some(config),
                        _ => None,
                    }))
            })
            .unwrap()
            .unwrap()
    };
    assert_eq!(stored_totp().source_representation.as_deref(), Some(source));
    assert_eq!(service.totp_for_human(&created.id).unwrap().0.len(), 6);
    let updated_source = format!("{source}&digits=8&period=45");
    let updated = service
        .update_entry(
            &owner,
            &created.id,
            EntryPatch {
                totp_uri: Some(updated_source.clone()),
                ..Default::default()
            },
            created.revision,
            "totp-update",
            false,
        )
        .unwrap();
    assert!(updated.has_totp);
    assert_eq!(service.totp_for_human(&created.id).unwrap().0.len(), 8);
    assert!(
        service
            .update_entry(
                &owner,
                &created.id,
                EntryPatch {
                    totp_uri: Some(format!("{source}&period=0")),
                    ..Default::default()
                },
                updated.revision,
                "totp-invalid",
                false
            )
            .is_err()
    );
    assert_eq!(
        stored_totp().source_representation.as_deref(),
        Some(updated_source.as_str())
    );
    assert_eq!(stored_totp().digits, 8);
    assert_eq!(stored_totp().period, 45);
    assert_eq!(service.totp_for_human(&created.id).unwrap().0.len(), 8);
}

#[test]
fn password_generator_and_totp() {
    assert_eq!(generate_password(32).unwrap().len(), 32);
    let random = generate_password_with_recipe(&PasswordRecipe::Random {
        length: 24,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        avoid_ambiguous: true,
    })
    .unwrap();
    assert_eq!(random.len(), 24);
    assert!(random.chars().any(|value| value.is_ascii_uppercase()));
    assert!(random.chars().any(|value| value.is_ascii_lowercase()));
    assert!(random.chars().any(|value| value.is_ascii_digit()));
    assert!(random.chars().any(|value| !value.is_ascii_alphanumeric()));
    assert!(!random.chars().any(|value| "0O1l".contains(value)));
    let words = generate_password_with_recipe(&PasswordRecipe::Words {
        count: 5,
        separator: "-".into(),
        capitalize: true,
        include_number: true,
    })
    .unwrap();
    assert_eq!(words.split('-').count(), 5);
    assert!(words.chars().any(|value| value.is_ascii_digit()));
    let pin = generate_password_with_recipe(&PasswordRecipe::Pin { length: 8 }).unwrap();
    assert_eq!(pin.len(), 8);
    assert!(pin.chars().all(|value| value.is_ascii_digit()));
    assert!(
        generate_password_with_recipe(&PasswordRecipe::Random {
            length: 24,
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            avoid_ambiguous: true,
        })
        .is_err()
    );
    let config = TotpConfig {
        secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
        issuer: None,
        account: None,
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        source_representation: None,
    };
    let (code, left) = current_totp(&config).unwrap();
    assert_eq!(code.len(), 6);
    assert!((1..=30).contains(&left));
    let legacy_short = TotpConfig {
        secret_base32: "JBSWY3DPEHPK3PXP".into(),
        ..config.clone()
    };
    assert_eq!(current_totp(&legacy_short).unwrap().0.len(), 6);
    let mut parsed = None;
    let mut uri = Some("otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30".into());
    normalize_totp(&mut parsed, &mut uri).unwrap();
    let parsed = parsed.unwrap();
    assert_eq!(parsed.issuer.as_deref(), Some("Example"));
    assert_eq!(parsed.account.as_deref(), Some("alice"));
    assert_eq!(parsed.period, 30);
}
#[tokio::test]
async fn google_oauth_pkce_picker_callback_is_state_bound() {
    let (_dir, service, actor) = service();
    let start = service
        .begin_google_oauth(&actor, "123456789-example.apps.googleusercontent.com", None)
        .await
        .unwrap();
    let authorization = url::Url::parse(&start.authorization_url).unwrap();
    assert_eq!(authorization.host_str(), Some("accounts.google.com"));
    let parameters = authorization
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(
        parameters.get("scope").map(String::as_str),
        Some(GOOGLE_OAUTH_SCOPE)
    );
    assert_eq!(
        parameters.get("trigger_onepick").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        parameters.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert!(parameters.contains_key("code_challenge"));
    assert!(!start.authorization_url.contains("pkce_"));
    let redirect = url::Url::parse(parameters.get("redirect_uri").unwrap()).unwrap();

    async fn callback(redirect: &url::Url, state: &str) -> String {
        let mut callback = redirect.clone();
        callback
            .query_pairs_mut()
            .append_pair("code", "authorization-code-secret")
            .append_pair("picked_file_ids", "file_1,file-2")
            .append_pair("scope", GOOGLE_OAUTH_SCOPE)
            .append_pair("state", state);
        let target = format!(
            "{}?{}",
            callback.path(),
            callback.query().unwrap_or_default()
        );
        let mut stream = tokio::net::TcpStream::connect((
            redirect.host_str().unwrap(),
            redirect.port().unwrap(),
        ))
        .await
        .unwrap();
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    assert!(
        callback(&redirect, "wrong-state")
            .await
            .starts_with("HTTP/1.1 403")
    );
    assert!(
        callback(&redirect, parameters.get("state").unwrap())
            .await
            .starts_with("HTTP/1.1 200")
    );
    let flows = service.google_oauth_flows.lock().unwrap();
    let flow = flows.get(&start.flow_id).unwrap();
    let GoogleOAuthCallback::Received {
        code,
        picked_file_ids,
        scope,
    } = &flow.callback
    else {
        panic!("callback was not captured");
    };
    assert_eq!(code, "authorization-code-secret");
    assert_eq!(picked_file_ids, &["file_1", "file-2"]);
    assert_eq!(scope, GOOGLE_OAUTH_SCOPE);
    drop(flows);
    service.lock().unwrap();
    assert!(service.google_oauth_flows.lock().unwrap().is_empty());
}
#[test]
fn google_picker_metadata_maps_to_exact_canonical_resources() {
    for (mime_type, expected) in [
        (
            "application/vnd.google-apps.document",
            "google:document/file_1",
        ),
        (
            "application/vnd.google-apps.spreadsheet",
            "google:spreadsheet/file_1",
        ),
        ("application/vnd.google-apps.folder", "google:folder/file_1"),
        ("application/pdf", "google:file/file_1"),
    ] {
        let metadata = serde_json::json!({"id":"file_1","mimeType":mime_type});
        assert_eq!(
            canonical_google_picker_resource("file_1", &metadata).unwrap(),
            expected
        );
    }
    let mismatched = serde_json::json!({
        "id":"file_2",
        "mimeType":"application/vnd.google-apps.document"
    });
    assert!(canonical_google_picker_resource("file_1", &mismatched).is_err());
}
#[tokio::test]
async fn fake_connector_lease_replay_restart_and_budget_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("lease.sqlite");
    let store = Arc::new(NativeStore::open(&db).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, client_token) = service.register_client("connector").unwrap();
    let actor = service
        .authenticate(&agent, &client_token, "stable-session")
        .unwrap();
    let connection = service
        .add_connection(
            "fake",
            "upstream-fixture-secret".into(),
            vec!["fake:resource/1".into()],
        )
        .unwrap();
    service
        .add_grant(PolicyRule {
            id: "fake-write".into(),
            version: 7,
            effect: PolicyEffect::Allow,
            agent_id: Some(agent.clone()),
            connection_id: Some(connection.id.0.clone()),
            resource_prefix: "fake:resource/1".into(),
            actions: vec!["fake.resource.write".into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 60,
            max_uses: 1,
            budget: DataBudget {
                max_items: Some(2),
                max_response_bytes: Some(1024),
                ..Default::default()
            },
        })
        .unwrap();
    let request = ActionRequest {
        schema_version: 1,
        request_id: RequestId::new(),
        subject: actor.clone(),
        task_id: Some(TaskId("task-conformance".into())),
        connection_id: connection.id.clone(),
        resource: "fake:resource/1".into(),
        action: "fake.resource.write".into(),
        arguments: serde_json::json!({"value":"external-content-must-not-enter-audit"}),
        idempotency_key: "side-effect-1".into(),
    };
    let mut scope_alias = request.clone();
    scope_alias.resource = "fake:resource/1/other-object".into();
    assert!(matches!(
        service
            .request_lease(&actor, scope_alias, 60, 1, None)
            .await,
        Err(KeyLeaseError::Denied { .. })
    ));
    let lease = match service
        .request_lease(&actor, request.clone(), 60, 1, None)
        .await
        .unwrap()
    {
        LeaseRequestOutcome::Issued { lease } => lease,
        _ => panic!("unexpected approval"),
    };
    let first = service
        .execute(&actor, &lease.token, request.clone())
        .await
        .unwrap();
    assert_eq!(first.body, serde_json::json!({"written":true}));
    drop(service);
    let reopened = KeyLeaseService::new(Arc::new(NativeStore::open(&db).unwrap())).unwrap();
    reopened.unlock(b"password", Duration::hours(1)).unwrap();
    let actor = reopened
        .authenticate(&agent, &client_token, "stable-session")
        .unwrap();
    assert!(matches!(
        reopened
            .execute(&actor, &lease.token, request.clone())
            .await,
        Err(KeyLeaseError::Denied { .. })
    ));
    let mut second = request;
    second.idempotency_key = "side-effect-2".into();
    assert!(matches!(
        reopened.execute(&actor, &lease.token, second).await,
        Err(KeyLeaseError::Denied { .. })
    ));
    let audits = reopened.audit_query(50).unwrap();
    let raw = serde_json::to_string(&audits).unwrap();
    assert!(!raw.contains("upstream-fixture-secret"));
    assert!(!raw.contains("external-content-must-not-enter-audit"));
}
#[tokio::test]
async fn connection_registry_cannot_repoint_to_an_invalid_credential_item() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("connection.sqlite")).unwrap());
    let service = KeyLeaseService::new(store.clone()).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let connection = service
        .add_connection("fake", "credential".into(), vec!["fake:resource/1".into()])
        .unwrap();

    let unlocked = store.unlock(b"password").unwrap();
    let item_id = ItemId(connection.credential_item_id);
    let mut item = store.get_item(&unlocked, &item_id).unwrap();
    item.issuer = Some("different-provider".into());
    item.revision += 1;
    store
        .put_item(
            &unlocked,
            &item,
            Some(1),
            MutationContext {
                actor: "tamper-test",
                idempotency_key: "tamper-credential",
                request_material: b"tamper-credential",
                audit_event: None,
            },
        )
        .unwrap();

    assert!(matches!(
        service.test_connection(&connection.id).await,
        Err(KeyLeaseError::Crypto)
    ));
}
#[tokio::test]
async fn approval_is_consumable_only_for_the_exact_canonical_request() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("approval.sqlite")).unwrap());
    let service = KeyLeaseService::new(store.clone()).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_client("approval").unwrap();
    let actor = service
        .authenticate(&agent, &token, "approval-session")
        .unwrap();
    let connection = service
        .add_connection("fake", "credential".into(), vec!["fake:resource/1".into()])
        .unwrap();
    service
        .add_grant(PolicyRule {
            id: "approved-write".into(),
            version: 2,
            effect: PolicyEffect::RequireApproval,
            agent_id: Some(agent),
            connection_id: Some(connection.id.0.clone()),
            resource_prefix: "fake:resource/1".into(),
            actions: vec!["fake.resource.write".into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 60,
            max_uses: 1,
            budget: Default::default(),
        })
        .unwrap();
    let request = ActionRequest {
        schema_version: 1,
        request_id: RequestId::new(),
        subject: actor.clone(),
        task_id: Some(TaskId("task-approved-write".into())),
        connection_id: connection.id,
        resource: "fake:resource/1".into(),
        action: "fake.resource.write".into(),
        arguments: serde_json::json!({"value":"approved"}),
        idempotency_key: "approval-idem".into(),
    };
    let approval = match service
        .request_lease(&actor, request.clone(), 30, 1, None)
        .await
        .unwrap()
    {
        LeaseRequestOutcome::ApprovalRequired { approval } => approval,
        _ => panic!("approval expected"),
    };
    assert_eq!(approval.task_id, request.task_id);
    let summary = approval.semantic_summary.as_ref().unwrap();
    assert_eq!(summary.operation, "fake.resource.write");
    assert_eq!(summary.changed_fields, ["value"]);
    assert!(!serde_json::to_string(summary).unwrap().contains("approved"));
    service.approve(&approval.id.0).unwrap();
    let mut changed = request.clone();
    changed.arguments = serde_json::json!({"value":"changed-after-approval"});
    assert!(matches!(
        service
            .request_lease(&actor, changed, 30, 1, Some(&approval.id.0))
            .await,
        Err(KeyLeaseError::Denied { .. })
    ));
    assert!(matches!(
        service
            .request_lease(&actor, request.clone(), 61, 1, Some(&approval.id.0))
            .await,
        Err(KeyLeaseError::Denied { .. })
    ));
    assert_eq!(
        store.get_approval(&approval.id.0).unwrap().state,
        ApprovalState::Approved
    );
    assert!(matches!(
        service
            .request_lease(&actor, request, 30, 1, Some(&approval.id.0))
            .await
            .unwrap(),
        LeaseRequestOutcome::Issued { .. }
    ));
    assert_eq!(
        store.get_approval(&approval.id.0).unwrap().state,
        ApprovalState::Consumed
    );
    let audit = service.audit_query(20).unwrap();
    assert!(
        audit
            .iter()
            .any(|event| { event.decision == "require_approval" && event.outcome == "pending" })
    );
    assert!(
        audit
            .iter()
            .any(|event| { event.action == "approval:decide" && event.outcome == "approved" })
    );
}

#[test]
fn desktop_owner_authority_is_rebuilt_after_every_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_desktop_client().unwrap();
    let actor = service
        .authenticate(&agent, &token, "desktop-session")
        .unwrap();

    for _ in 0..2 {
        service.lock().unwrap();
        service
            .unlock_for_client(&agent, b"password", Duration::hours(1))
            .unwrap();
        assert!(service.list_groups_authorized(&actor).is_ok());
    }
}

#[test]
fn wrong_master_password_is_reported_as_rejected_not_crypto() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service
        .initialize(b"correct password", Duration::hours(1))
        .unwrap();
    let (agent, _) = service.register_desktop_client().unwrap();
    service.lock().unwrap();

    assert_eq!(
        service
            .unlock_for_client(&agent, b"wrong password", Duration::hours(1))
            .unwrap_err(),
        KeyLeaseError::Denied {
            reason: "master password rejected".into(),
        },
    );
    assert!(service.status().unwrap()["locked"].as_bool().unwrap());
    assert!(
        service
            .unlock_for_client(&agent, b"correct password", Duration::hours(1))
            .is_ok()
    );
}

#[test]
fn registered_agent_can_manage_shared_content_without_grants() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_client("writer").unwrap();
    let actor = service
        .authenticate(&agent, &token, "writer-session")
        .unwrap();

    let project = service
        .create_project_agent(&actor, "leasegate", Some("Leasegate"), "project-create")
        .unwrap();
    assert_eq!(project.slug, "leasegate");
    assert_eq!(service.list_projects_agent(&actor).unwrap(), vec![project]);

    let created = service
        .create_content(
            &actor,
            ContentCreateInput {
                favorite: false,
                kind: "core.runbook".into(),
                title: "Release safely".into(),
                body: "# Release\n\nRun checks first.".into(),
                tags: vec!["release".into(), "ops".into()],
                project_slug: Some("leasegate".into()),
            },
            "content-create",
        )
        .unwrap();
    assert_eq!(created.summary.agent_access, AgentAccess::ReadWrite);
    assert_eq!(
        created.summary.content_metadata.review_state,
        ContentReviewState::Unreviewed
    );
    assert_eq!(created.summary.project_slug.as_deref(), Some("leasegate"));
    assert_eq!(
        service
            .get_content(&actor, &created.summary.id)
            .unwrap()
            .body,
        created.body
    );

    let updated = service
        .update_content(
            &actor,
            &created.summary.id,
            ContentPatch {
                body: Some("# Release\n\nRun all checks first.".into()),
                add_tags: vec!["verified-later".into()],
                ..ContentPatch::default()
            },
            created.summary.revision,
            "content-update",
        )
        .unwrap();
    assert_eq!(updated.summary.revision, created.summary.revision + 1);
    assert!(updated.summary.tags.contains(&"verified-later".into()));
    assert_eq!(
        service
            .search_content(
                &actor,
                "all checks",
                Some("runbook"),
                None,
                Some("leasegate"),
                false
            )
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        service.set_content_access(
            &actor,
            &updated.summary.id,
            AgentAccess::None,
            updated.summary.revision,
            "content-access",
        ),
        Err(KeyLeaseError::Denied { .. })
    ));
    let (owner_id, owner_token) = service.register_desktop_client().unwrap();
    let owner = service
        .authenticate(&owner_id, &owner_token, "owner-session")
        .unwrap();
    let private = service
        .set_content_access(
            &owner,
            &updated.summary.id,
            AgentAccess::None,
            updated.summary.revision,
            "owner-content-access",
        )
        .unwrap();
    assert_eq!(private.summary.agent_access, AgentAccess::None);
    assert!(matches!(
        service.get_content(&actor, &private.summary.id),
        Err(KeyLeaseError::NotFound { .. })
    ));
    let reviewed = service
        .review_content(
            &owner,
            &private.summary.id,
            private.summary.revision,
            "owner-content-review",
        )
        .unwrap();
    assert_eq!(
        reviewed.summary.content_metadata.review_state,
        ContentReviewState::HumanReviewed
    );
}

#[test]
fn content_channel_obeys_global_kill_switch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_client("writer").unwrap();
    let actor = service
        .authenticate(&agent, &token, "writer-session")
        .unwrap();
    service.kill_switch(true).unwrap();
    assert!(matches!(
        service.search_content(&actor, "", None, None, None, false),
        Err(KeyLeaseError::Denied { .. })
    ));
    assert!(matches!(
        service.create_project_agent(&actor, "blocked", None, "blocked-project"),
        Err(KeyLeaseError::Denied { .. })
    ));
}

#[test]
fn an_ordinary_client_never_receives_desktop_owner_authority() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    let (agent, token) = service.register_client("desktop-lookalike").unwrap();
    let actor = service
        .authenticate(&agent, &token, "ordinary-session")
        .unwrap();
    service.lock().unwrap();
    service
        .unlock_for_client(&agent, b"password", Duration::hours(1))
        .unwrap();
    assert!(matches!(
        service.list_groups_authorized(&actor),
        Err(KeyLeaseError::Denied { .. })
    ));
}

#[test]
fn environment_sections_preserve_order_and_validate_names() {
    let make = |key: &str, role: &str, value: &str, protected: bool| {
        let mut field = field(
            key,
            key.strip_prefix("env.").unwrap_or(key),
            if protected {
                FieldValue::Concealed(value.into())
            } else {
                FieldValue::Text(value.into())
            },
            if protected {
                Sensitivity::HighlySensitive
            } else {
                Sensitivity::PrivateMetadata
            },
            protected,
        );
        field.semantic_role = Some(role.into());
        field
    };
    let fields = vec![
        make(
            "environment.project",
            "environment_project",
            "leasegate",
            false,
        ),
        make(
            "environment.scope",
            "environment_scope",
            "development",
            false,
        ),
        make("environment.source", "environment_source", "dotenv", false),
        make("env.API_TOKEN", "environment_variable", "secret", true),
        make("env.PORT", "environment_variable", "8080", false),
    ];
    let sections = vec![
        ItemSection {
            id: "environment_metadata".into(),
            label: "Environment".into(),
            field_ids: fields[..3].iter().map(|field| field.id.clone()).collect(),
            semantic_role: Some("environment_metadata".into()),
        },
        ItemSection {
            id: "environment_variables".into(),
            label: "Variables".into(),
            field_ids: fields[3..].iter().map(|field| field.id.clone()).collect(),
            semantic_role: Some("environment_variables".into()),
        },
    ];
    validate_sections(&sections, &fields).unwrap();
    validate_specialized_item("core.environment", &sections, &fields).unwrap();

    let mut invalid = fields.clone();
    invalid[4].key = "env.BAD-NAME".into();
    invalid[4].label = "BAD-NAME".into();
    assert!(matches!(
        validate_specialized_item("core.environment", &sections, &invalid),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
}

#[test]
fn ssh_jump_host_cycles_are_rejected() {
    fn endpoint(id: &str, alias: &str, parent: &str) -> (ItemSection, Vec<ItemField>) {
        let values = [
            ("ssh_display_name", alias),
            ("ssh_alias", alias),
            ("ssh_host", "example.internal"),
            ("ssh_port", "22"),
            ("ssh_auth_mode", "ssh_agent"),
            ("ssh_sudo_mode", "none"),
            ("ssh_connect_via", parent),
        ];
        let fields = values
            .into_iter()
            .map(|(role, value)| {
                let mut field = field(
                    &format!("ssh.{id}.{role}"),
                    role,
                    FieldValue::Text(value.into()),
                    Sensitivity::PrivateMetadata,
                    false,
                );
                field.semantic_role = Some(role.into());
                field
            })
            .collect::<Vec<_>>();
        let section = ItemSection {
            id: id.into(),
            label: alias.into(),
            field_ids: fields.iter().map(|field| field.id.clone()).collect(),
            semantic_role: Some("ssh_endpoint".into()),
        };
        (section, fields)
    }
    let (first, mut fields) = endpoint("bastion", "bastion", "target");
    let (second, second_fields) = endpoint("target", "target", "bastion");
    fields.extend(second_fields);
    assert!(matches!(
        validate_specialized_item("core.ssh_server", &[first, second], &fields),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
}

#[test]
fn batch_reveal_is_bounded_and_returns_only_requested_field_ids() {
    let (_dir, service, actor) = service();
    let group = service.create_group("Development", None).unwrap();
    let field_id = FieldId::new();
    let created = service
        .create_entry(
            &actor,
            NewEntryInput {
                group_id: group.id,
                kind: "core.api_credential".into(),
                title: "Deploy token".into(),
                project_slug: None,
                favorite: false,
                username: None,
                password: None,
                url: None,
                notes: None,
                custom_fields: vec![ItemField {
                    id: field_id.clone(),
                    key: "credential".into(),
                    label: "Token".into(),
                    value: FieldValue::Concealed("secret-token".into()),
                    sensitivity: Sensitivity::HighlySensitive,
                    protected: true,
                    semantic_role: Some("credential".into()),
                }],
                sections: vec![],
                totp: None,
                totp_uri: None,
                environment: None,
                personal: false,
            },
            "batch-create",
            false,
        )
        .unwrap();
    service
        .add_grant(PolicyRule {
            id: "batch-read-secret".into(),
            version: 1,
            effect: PolicyEffect::Allow,
            agent_id: Some(actor.agent_id.clone()),
            connection_id: None,
            resource_prefix: format!("kl://{}", group.vault_id.0),
            actions: vec!["entry:read_secret".into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 60,
            max_uses: 10,
            budget: Default::default(),
        })
        .unwrap();
    let values = service
        .reveal_fields_by_id_authorized(&actor, &created.id, std::slice::from_ref(&field_id))
        .unwrap();
    assert_eq!(
        values.get(&field_id.0),
        Some(&FieldValue::Concealed("secret-token".into()))
    );
    assert!(matches!(
        service.reveal_fields_by_id_authorized(&actor, &created.id, &[]),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
}

fn grant(service: &KeyLeaseService, actor: &ActorContext, action: &str, resource: String) {
    service
        .add_grant(PolicyRule {
            id: format!("{}-{action}", actor.agent_id.0),
            version: 1,
            effect: PolicyEffect::Allow,
            agent_id: Some(actor.agent_id.clone()),
            connection_id: None,
            resource_prefix: resource,
            actions: vec![action.into()],
            argument_equals: Default::default(),
            not_before: None,
            expires_at: None,
            max_lease_ttl_seconds: 600,
            max_uses: 100,
            budget: Default::default(),
        })
        .unwrap();
}

/// A vault with a desktop owner and an agent holding the usual test grants.
fn service_with_owner() -> (
    tempfile::TempDir,
    KeyLeaseService,
    ActorContext,
    ActorContext,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    let vault = service.initialize(b"password", Duration::hours(1)).unwrap();
    let (owner_id, owner_token) = service.register_desktop_client().unwrap();
    // Owner authority is installed when the owner client unlocks.
    service.lock().unwrap();
    service
        .unlock_for_client(&owner_id, b"password", Duration::hours(1))
        .unwrap();
    let owner = service
        .authenticate(&owner_id, &owner_token, "owner-session")
        .unwrap();
    let (agent_id, agent_token) = service.register_client("test").unwrap();
    let agent = service
        .authenticate(&agent_id, &agent_token, "agent-session")
        .unwrap();
    for action in [
        "entry:create",
        "entry:search",
        "entry:update_standard_fields",
        "entry:update_protected_fields",
    ] {
        grant(&service, &agent, action, format!("kl://{}", vault.0));
    }
    (dir, service, owner, agent)
}

fn login_input(group: &VaultGroup, title: &str) -> NewEntryInput {
    NewEntryInput {
        group_id: group.id.clone(),
        kind: "core.login".into(),
        title: title.into(),
        project_slug: None,
        favorite: false,
        username: Some("me".into()),
        password: Some("hunter2-personal".into()),
        url: None,
        notes: None,
        custom_fields: vec![],
        sections: vec![],
        totp: None,
        totp_uri: None,
        environment: None,
        personal: false,
    }
}

#[test]
fn personal_items_do_not_exist_for_agents() {
    let (_dir, service, owner, agent) = service_with_owner();
    let group = service.create_group("Personal", None).unwrap();
    let vault = group.vault_id.0.clone();
    for action in [
        "entry:read_metadata",
        "entry:read_secret",
        "entry:inject_secret",
    ] {
        grant(&service, &agent, action, format!("kl://{vault}"));
    }
    // Agents cannot create personal items, the owner can.
    let mut input = login_input(&group, "Bank");
    input.personal = true;
    assert!(matches!(
        service.create_entry(&agent, input.clone(), "agent-personal", false),
        Err(KeyLeaseError::Denied { .. })
    ));
    let bank = service
        .create_entry(&owner, input, "owner-personal", false)
        .unwrap();
    assert!(bank.personal);
    let work = service
        .create_entry(&agent, login_input(&group, "Work"), "work", false)
        .unwrap();

    let titles = |actor: &ActorContext| {
        service
            .search_entries(actor, "")
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect::<Vec<_>>()
    };
    assert_eq!(titles(&agent), vec!["Work".to_string()]);
    assert!(titles(&owner).contains(&"Bank".to_string()));
    // Every command on the item fails as not found, despite the grants.
    assert!(matches!(
        service.get_entry_metadata(&agent, &bank.id),
        Err(KeyLeaseError::NotFound { .. })
    ));
    assert!(matches!(
        service.reveal_field_authorized(&agent, &bank.id, "password"),
        Err(KeyLeaseError::NotFound { .. })
    ));
    assert!(matches!(
        service.inject_fields_authorized(
            &agent,
            "env",
            &[],
            &[InjectRequest {
                item_id: bank.id.clone(),
                field: "password".into()
            }]
        ),
        Err(KeyLeaseError::NotFound { .. })
    ));
    assert!(service.get_entry_metadata(&agent, &work.id).is_ok());
    // Only the owner moves items into or out of the Personal area.
    let patch = EntryPatch {
        personal: Some(true),
        ..Default::default()
    };
    assert!(matches!(
        service.update_entry(
            &agent,
            &work.id,
            patch.clone(),
            work.revision,
            "agent-hide",
            false
        ),
        Err(KeyLeaseError::Denied { .. })
    ));
    let hidden = service
        .update_entry(&owner, &work.id, patch, work.revision, "owner-hide", false)
        .unwrap();
    assert!(hidden.personal);
    assert!(titles(&agent).is_empty());
}

#[test]
fn project_environments_validate_items_and_protect_production() {
    let (_dir, service, owner, agent) = service_with_owner();
    let group = service.create_group("Shop", None).unwrap();
    let project = service
        .create_project_agent(&owner, "shop", Some("Shop"), "project-shop")
        .unwrap();
    // New projects start with dev, staging and a protected production.
    assert_eq!(
        project
            .environments
            .iter()
            .map(|environment| (environment.slug.as_str(), environment.protected))
            .collect::<Vec<_>>(),
        vec![("dev", false), ("staging", false), ("production", true)]
    );
    let mut input = login_input(&group, "Stripe");
    input.password = None;
    input.project_slug = Some("shop".into());
    input.environment = Some("qa".into());
    assert!(matches!(
        service.create_entry(&agent, input.clone(), "bad-env", false),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
    input.environment = Some("Production".into());
    let item = service
        .create_entry(&agent, input, "prod-env", false)
        .unwrap();
    // Stored as the slug.
    assert_eq!(item.environment.as_deref(), Some("production"));
    let stored = service
        .with_vault(|vault| service.store.get_item(vault, &item.id))
        .unwrap();
    assert!(
        service
            .with_vault(|vault| service.item_environment_protected(vault, &stored))
            .unwrap()
    );

    // A client allowed only standard-field edits cannot move the item out of
    // production; that lowers its risk tier, so it is a protected change.
    let (limited_id, limited_token) = service.register_client("limited").unwrap();
    let limited = service
        .authenticate(&limited_id, &limited_token, "limited")
        .unwrap();
    let vault = group.vault_id.0.clone();
    grant(
        &service,
        &limited,
        "entry:update_standard_fields",
        format!("kl://{vault}"),
    );
    let to_dev = EntryPatch {
        environment: Some("dev".into()),
        ..Default::default()
    };
    assert!(
        service
            .update_entry(
                &limited,
                &item.id,
                to_dev.clone(),
                item.revision,
                "limited-dev",
                false
            )
            .is_err()
    );
    let moved = service
        .update_entry(&agent, &item.id, to_dev, item.revision, "agent-dev", false)
        .unwrap();
    assert_eq!(moved.environment.as_deref(), Some("dev"));

    // Environments are managed by the owner; one in use cannot be removed.
    let updated = service
        .set_project_environment("shop", "qa", Some("QA"), false)
        .unwrap();
    assert!(updated.environment("qa").is_some());
    assert!(service.remove_project_environment("shop", "dev").is_err());
    assert!(service.remove_project_environment("shop", "qa").is_ok());
    assert!(
        service
            .set_project_environment("shop", "Not Valid", None, false)
            .is_err()
    );
}

#[test]
fn named_references_resolve_to_project_items() {
    let (_dir, service, owner, agent) = service_with_owner();
    let group = service.create_group("Shop", None).unwrap();
    service
        .create_project_agent(&owner, "shop", None, "project-shop")
        .unwrap();
    let vault = group.vault_id.0.clone();
    grant(
        &service,
        &agent,
        "entry:inject_secret",
        format!("kl://{vault}"),
    );
    for (environment, secret) in [
        ("staging", "sk_test_staging"),
        ("production", "sk_live_prod"),
    ] {
        let mut input = login_input(&group, "Stripe");
        input.project_slug = Some("shop".into());
        input.environment = Some(environment.into());
        input.password = Some(secret.into());
        service
            .create_entry(&agent, input, &format!("stripe-{environment}"), false)
            .unwrap();
    }
    let request = |path: &str, field: &str| InjectRequest {
        item_id: ItemId(format!("ref:{path}")),
        field: field.into(),
    };
    let values = service
        .inject_fields_authorized(
            &agent,
            "env",
            &[],
            &[request("shop/staging/stripe", "password")],
        )
        .unwrap();
    assert_eq!(values, vec!["sk_test_staging".to_string()]);
    // Without the environment the name is ambiguous.
    assert!(matches!(
        service.inject_fields_authorized(&agent, "env", &[], &[request("shop/Stripe", "password")]),
        Err(KeyLeaseError::InvalidRequest { .. })
    ));
    assert!(matches!(
        service.inject_fields_authorized(
            &agent,
            "env",
            &[],
            &[request("shop/staging/missing", "password")]
        ),
        Err(KeyLeaseError::NotFound { .. })
    ));
}

fn bare_vault() -> (tempfile::TempDir, KeyLeaseService) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(NativeStore::open(dir.path().join("vault.sqlite")).unwrap());
    let service = KeyLeaseService::new(store).unwrap();
    service.initialize(b"password", Duration::hours(1)).unwrap();
    (dir, service)
}

#[test]
fn bundles_move_a_project_between_nodes_and_keep_it_in_sync() {
    let (_mac_dir, mac, owner, agent) = service_with_owner();
    let (_vps_dir, vps) = bare_vault();
    let (_other_dir, other) = bare_vault();
    let group = mac.create_group("Servers", None).unwrap();
    mac.create_project_agent(&owner, "shop", None, "project-shop")
        .unwrap();
    let mut input = login_input(&group, "Postgres");
    input.project_slug = Some("shop".into());
    input.environment = Some("production".into());
    input.password = Some("db-password-1".into());
    let item = mac.create_entry(&agent, input, "pg", false).unwrap();
    let mut personal = login_input(&group, "Bank");
    personal.personal = true;
    personal.project_slug = Some("shop".into());
    mac.create_entry(&owner, personal, "bank", false).unwrap();

    let vps_id = vps.node_identity().unwrap();
    assert!(vps_id.node_id.starts_with("age1"));
    assert_eq!(
        vps.node_identity().unwrap(),
        vps_id,
        "the identity is stable"
    );
    let selection = BundleSelection {
        project_slug: Some("shop".into()),
        item_ids: vec![],
    };
    let bundle = mac
        .export_bundle(&vps_id.node_id, &selection, Some("mac"))
        .unwrap();
    assert!(bundle.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(!bundle.contains("db-password-1"));

    // Another node cannot open it.
    assert!(other.import_bundle(&bundle, None, false).is_err());
    // A first-time sender must be confirmed by fingerprint.
    let preview = vps.preview_bundle(&bundle).unwrap();
    assert!(!preview.known_sender);
    assert_eq!(
        preview.items,
        vec!["Postgres".to_string()],
        "personal items stay home"
    );
    assert!(vps.import_bundle(&bundle, None, false).is_err());
    assert!(vps.import_bundle(&bundle, Some("00:11"), false).is_err());
    let report = vps
        .import_bundle(&bundle, Some(&preview.sender_fingerprint), false)
        .unwrap();
    assert_eq!((report.created, report.updated), (1, 0));
    assert_eq!(report.projects_created, vec!["shop".to_string()]);
    let (imported_id, environment) = vps
        .with_vault(|vault| {
            let items = vps.store.list_items(vault)?;
            let project = vps.store.list_projects(vault)?.remove(0);
            assert_eq!(
                project.environment("production").map(|e| e.protected),
                Some(true)
            );
            let item = items
                .into_iter()
                .find(|item| item.title == "Postgres")
                .unwrap();
            assert_eq!(item.project_id.as_ref(), Some(&project.id));
            Ok((item.id, item.environment))
        })
        .unwrap();
    assert_eq!(environment.as_deref(), Some("production"));
    assert_eq!(
        vps.reveal_field_for_human(&imported_id, "password")
            .unwrap(),
        "db-password-1"
    );
    // Read-only: edits are refused on the receiving node.
    let (vps_agent, vps_token) = vps.register_client("vps-agent").unwrap();
    let vps_actor = vps.authenticate(&vps_agent, &vps_token, "s").unwrap();
    assert!(matches!(
        vps.update_entry(
            &vps_actor,
            &imported_id,
            EntryPatch {
                title: Some("x".into()),
                ..Default::default()
            },
            1,
            "edit",
            false
        ),
        Err(KeyLeaseError::Denied { .. })
    ));

    // The same bundle again changes nothing; a newer revision updates in place.
    assert_eq!(
        vps.import_bundle(&bundle, None, false).unwrap().unchanged,
        1
    );
    mac.update_entry(
        &agent,
        &item.id,
        EntryPatch {
            password: Some("db-password-2".into()),
            ..Default::default()
        },
        item.revision,
        "rotate",
        false,
    )
    .unwrap();
    let newer = mac
        .export_bundle(&vps_id.node_id, &selection, None)
        .unwrap();
    let report = vps.import_bundle(&newer, None, false).unwrap();
    assert_eq!((report.created, report.updated), (0, 1));
    assert_eq!(
        vps.reveal_field_for_human(&imported_id, "password")
            .unwrap(),
        "db-password-2"
    );
    // Editable imports are independent copies.
    let copy = vps.import_bundle(&newer, None, true).unwrap();
    assert_eq!(copy.created, 1);
}

#[test]
fn a_bundle_is_a_standard_age_file() {
    if std::process::Command::new("age")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping: the age CLI is not installed");
        return;
    }
    let (_mac_dir, mac, owner, agent) = service_with_owner();
    let (dir, vps) = bare_vault();
    let group = mac.create_group("Servers", None).unwrap();
    mac.create_project_agent(&owner, "shop", None, "project-shop")
        .unwrap();
    let mut input = login_input(&group, "API");
    input.project_slug = Some("shop".into());
    mac.create_entry(&agent, input, "api", false).unwrap();
    let node = vps.node_identity().unwrap();
    let bundle = mac
        .export_bundle(
            &node.node_id,
            &BundleSelection {
                project_slug: Some("shop".into()),
                item_ids: vec![],
            },
            None,
        )
        .unwrap();
    let identity_file = dir.path().join("identity.txt");
    let secret = vps
        .with_vault(|vault| Ok(vps.bundle_keys(vault)?.0.to_string()))
        .unwrap();
    use age::secrecy::ExposeSecret;
    std::fs::write(&identity_file, secret.expose_secret()).unwrap();
    let bundle_file = dir.path().join("bundle.age");
    std::fs::write(&bundle_file, &bundle).unwrap();
    let output = std::process::Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(&identity_file)
        .arg(&bundle_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plaintext: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plaintext["format"], BUNDLE_FORMAT);
}

#[test]
fn env_files_and_csv_exports_import_as_items() {
    let (_dir, service, owner, agent) = service_with_owner();
    service
        .create_project_agent(&owner, "shop", None, "project-shop")
        .unwrap();
    let item = service
        .import_env_file(
            "DATABASE_URL=postgres://u:p@db/shop\nexport STRIPE_KEY=\"sk_live_1\"\n",
            "shop",
            Some("production"),
            ".env.production",
            "/srv/shop/.env.production",
        )
        .unwrap();
    assert_eq!(item.kind, "core.environment");
    assert_eq!(item.environment.as_deref(), Some("production"));
    assert!(
        service
            .import_env_file("A=1", "shop", Some("qa"), "x", "x")
            .is_err()
    );
    let vault = service
        .with_vault(|vault| Ok(vault.vault_id.0.clone()))
        .unwrap();
    grant(
        &service,
        &agent,
        "entry:inject_secret",
        format!("kl://{vault}"),
    );
    let values = service
        .inject_fields_authorized(
            &agent,
            "env",
            &[],
            &[InjectRequest {
                item_id: ItemId("ref:shop/production/.env.production".into()),
                field: "STRIPE_KEY".into(),
            }],
        )
        .unwrap();
    assert_eq!(values, vec!["sk_live_1".to_string()]);

    let report = service
        .import_logins_csv(
            "name,url,username,password,note\nBank,https://bank.example,me,pw1,\n,https://mail.example,me2,pw2,hi\nEmpty,,,,\n",
            "Imported",
        )
        .unwrap();
    assert_eq!((report.created, report.skipped), (2, 1));
    let titles: Vec<String> = service
        .search_entries(&owner, "")
        .unwrap()
        .into_iter()
        .filter(|item| item.personal)
        .map(|item| item.title)
        .collect();
    assert!(titles.contains(&"Bank".to_string()));
    assert!(titles.contains(&"mail.example".to_string()), "{titles:?}");
    // Imported logins are personal: invisible to agents.
    assert!(service.search_entries(&agent, "Bank").unwrap().is_empty());
}

/// A one-request HTTP server on loopback that echoes what it received,
/// including the Authorization header (to check scrubbing).
async fn echo_server() -> (u16, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = socket.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&request).into_owned();
        let authorization = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("authorization: ")
                    .or_else(|| line.strip_prefix("Authorization: "))
            })
            .unwrap_or("")
            .to_owned();
        let body = format!("{{\"you_sent\":\"{authorization}\"}}");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        text
    });
    (port, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn http_requests_get_the_credential_without_the_agent_seeing_it() {
    let (_dir, service, _owner, agent) = service_with_owner();
    let group = service.create_group("APIs", None).unwrap();
    let mut input = login_input(&group, "Local API");
    input.password = Some("sk_test_secret_123".into());
    let item = service.create_entry(&agent, input, "api", false).unwrap();
    let (port, server) = echo_server().await;
    let binding = |allow_private: bool| HttpBinding {
        base_url: format!("http://127.0.0.1:{port}/v1"),
        header: "Authorization".into(),
        template: "Bearer {secret}".into(),
        field: Some("password".into()),
        allow_private,
    };
    // Binding is a protected change; the fixture agent may make it.
    service
        .set_http_binding_authorized(&agent, &item.id, Some(binding(false)))
        .unwrap();
    let request = |path: &str| HttpForwardRequest {
        item_id: item.id.clone(),
        method: "GET".into(),
        path: path.into(),
        headers: vec![
            ("Authorization".into(), "Bearer placeholder".into()),
            ("x-trace".into(), "1".into()),
        ],
        body_b64: None,
    };
    // Without a grant (this agent is not enrolled) the request is denied.
    assert!(matches!(
        service
            .http_forward_authorized(&agent, request("/charges"))
            .await,
        Err(KeyLeaseError::Denied { .. })
    ));
    let vault = group.vault_id.0.clone();
    grant(&service, &agent, "http:request", format!("kl://{vault}"));
    // Loopback is refused unless the binding allows private addresses.
    assert!(matches!(
        service
            .http_forward_authorized(&agent, request("/charges"))
            .await,
        Err(KeyLeaseError::Denied { .. })
    ));
    service
        .set_http_binding_authorized(&agent, &item.id, Some(binding(true)))
        .unwrap();
    assert!(
        service
            .http_forward_authorized(&agent, request("/../admin"))
            .await
            .is_err()
    );
    let response = service
        .http_forward_authorized(&agent, request("/charges?limit=1"))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&response.body_b64)
            .unwrap(),
    )
    .unwrap();
    assert!(!body.contains("sk_test_secret_123"), "{body}");
    assert!(body.contains("[REDACTED by keylease]"), "{body}");
    let received = server.await.unwrap();
    assert!(
        received.starts_with("GET /v1/charges?limit=1 HTTP/1.1"),
        "{received}"
    );
    assert!(
        received.contains("Bearer sk_test_secret_123"),
        "the upstream got the real credential"
    );
    assert!(
        !received.contains("placeholder"),
        "the agent's own header was replaced"
    );
    assert!(received.contains("x-trace: 1"));
    // The binding is visible as metadata; only protected edits change it.
    grant(
        &service,
        &agent,
        "entry:read_metadata",
        format!("kl://{vault}"),
    );
    assert_eq!(
        service
            .http_binding_authorized(&agent, &item.id)
            .unwrap()
            .unwrap()
            .base_url,
        format!("http://127.0.0.1:{port}/v1")
    );
}
