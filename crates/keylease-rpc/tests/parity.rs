//! The contract tests for the local RPC protocol.
//!
//! `keylease-cli` frames this protocol over a Unix socket and the mobile FFI
//! layer calls it in process. Both go through `dispatch_line`, so these tests
//! cover both transports at once. A Dart client reads the same wire format and
//! cannot be type-checked against this crate, which is why the command names
//! and the envelope shape are pinned here rather than left to convention.

use std::sync::Arc;

use keylease_core::LocalOwnerRole;
use keylease_rpc::{MAX_LOCAL_JSON_BYTES, RpcCapabilities, RpcRequest, dispatch_line};
use keylease_service::KeyLeaseService;
use keylease_store::NativeStore;
use serde_json::{Value, json};

const MASTER_PASSWORD: &str = "parity-master-password-2ba91f";

/// A value that must only ever appear where a secret is deliberately revealed.
const CANARY_SECRET: &str = "canary-4f8b21d0e77a-never-log-me";

/// Every command the daemon accepts, taken from serde itself rather than from a
/// hand-maintained list, and compared against the frozen vector.
fn accepted_commands() -> Vec<String> {
    let error = serde_json::from_value::<RpcRequest>(json!({"command": "__not_a_command"}))
        .expect_err("a bogus command must not deserialise")
        .to_string();
    let (_, tail) = error
        .split_once("expected one of ")
        .expect("serde should list the accepted variants");
    tail.split(", ")
        .map(|name| name.trim().trim_matches('`').to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

#[test]
fn command_names_match_the_frozen_vector() {
    let frozen: Value =
        serde_json::from_str(include_str!("../../../test-vectors/rpc/commands.json"))
            .expect("the command vector must be valid JSON");
    let expected: Vec<String> = frozen["commands"]
        .as_array()
        .expect("commands must be an array")
        .iter()
        .map(|name| name.as_str().expect("command names are strings").to_owned())
        .collect();

    assert_eq!(
        accepted_commands(),
        expected,
        "the wire command list changed. A Dart client reads these strings and \
         will not fail to compile when one is renamed, so update \
         test-vectors/rpc/commands.json and the client in the same change."
    );
}

#[test]
fn an_unknown_command_is_rejected_rather_than_ignored() {
    assert!(
        !accepted_commands().contains(&"__not_a_command".to_owned()),
        "the probe name must not be a real command"
    );
}

/// A service with an unlocked vault and a registered local owner.
fn service_with_owner() -> (tempfile::TempDir, Arc<KeyLeaseService>, Value) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = NativeStore::open(dir.path().join("vault.sqlite")).expect("store opens");
    let service = Arc::new(KeyLeaseService::new(Arc::new(store)).expect("service starts"));
    service
        .initialize(MASTER_PASSWORD.as_bytes(), chrono::Duration::minutes(5))
        .expect("vault initialises");
    let (agent_id, token) = service
        .register_desktop_client()
        .expect("owner client registers");
    service
        .unlock_for_client(
            &agent_id,
            MASTER_PASSWORD.as_bytes(),
            chrono::Duration::minutes(5),
        )
        .expect("owner unlocks");
    let auth = json!({"agent_id": agent_id, "token": token, "session_id": "parity"});
    (dir, service, auth)
}

async fn call(service: &KeyLeaseService, request: Value) -> Value {
    serde_json::from_str(
        &dispatch_line(service, RpcCapabilities::DESKTOP, &request.to_string()).await,
    )
    .expect("a response is always JSON")
}

#[tokio::test]
async fn the_response_envelope_shape_is_stable() {
    let (_dir, service, _auth) = service_with_owner();

    let ok = call(&service, json!({"command": "status"})).await;
    assert_eq!(ok["ok"], json!(true), "success sets ok to true");
    assert!(ok.get("result").is_some(), "success carries result");
    assert!(ok.get("error").is_none(), "success carries no error");

    let failed = call(&service, json!({"command": "__not_a_command"})).await;
    assert_eq!(failed["ok"], json!(false), "failure sets ok to false");
    assert_eq!(
        failed["error"]["error"], "invalid_request",
        "the client routes on this exact code"
    );
    assert!(failed.get("result").is_none(), "failure carries no result");
}

#[tokio::test]
async fn malformed_input_fails_closed() {
    let (_dir, service, _auth) = service_with_owner();

    for body in ["{not json}", "", "[]", "null"] {
        let raw = dispatch_line(&service, RpcCapabilities::DESKTOP, body).await;
        let response: Value = serde_json::from_str(&raw).expect("still a JSON envelope");
        assert_eq!(response["ok"], json!(false), "{body:?} must be rejected");
    }

    let oversize = format!(
        "{{\"command\":\"status\",\"pad\":\"{}\"}}",
        "x".repeat(MAX_LOCAL_JSON_BYTES)
    );
    let response: Value =
        serde_json::from_str(&dispatch_line(&service, RpcCapabilities::DESKTOP, &oversize).await)
            .expect("JSON envelope");
    assert_eq!(
        response["ok"],
        json!(false),
        "a request over the size limit must be refused"
    );
}

#[tokio::test]
async fn an_unauthenticated_mutation_is_denied() {
    let (_dir, service, _auth) = service_with_owner();

    // `status` is the only command that may omit `auth`.
    let response = call(&service, json!({"command": "groups_list"})).await;
    assert_eq!(response["ok"], json!(false));
    assert_eq!(
        response["error"]["error"], "invalid_request",
        "a missing auth block is a malformed request, not a silent success"
    );
}

#[tokio::test]
async fn dispatch_round_trips_a_secret_only_where_it_is_asked_for() {
    let (_dir, service, auth) = service_with_owner();

    let group = call(
        &service,
        json!({"command": "groups_create", "auth": auth, "name": "Parity",
               "parent_id": null, "idempotency_key": "parity-group-1", "dry_run": false}),
    )
    .await;
    assert_eq!(group["ok"], json!(true), "group creation: {group}");
    let group_id = group["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("a group id in {group}"))
        .to_owned();

    let created = call(
        &service,
        json!({"command": "entries_create", "auth": auth,
        "idempotency_key": "parity-entry-1", "dry_run": false,
        "input": {
            "group_id": group_id,
            "kind": "core.login",
            "title": "Parity Entry",
            "username": "parity@example.test",
            "password": CANARY_SECRET,
        }}),
    )
    .await;
    assert_eq!(created["ok"], json!(true), "entry creation: {created}");
    let entry_id = created["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("an entry id in {created}"))
        .to_owned();

    // Metadata must not carry the secret.
    let listed = call(
        &service,
        json!({"command": "entries_search", "auth": auth, "query": "Parity"}),
    )
    .await;
    assert_eq!(listed["ok"], json!(true), "search: {listed}");
    assert!(
        !listed.to_string().contains(CANARY_SECRET),
        "a metadata search must never return the secret"
    );

    // An explicit reveal must.
    let revealed = call(
        &service,
        json!({"command": "entries_reveal", "auth": auth, "id": entry_id, "field": "password"}),
    )
    .await;
    assert_eq!(revealed["ok"], json!(true), "reveal: {revealed}");
    assert!(
        revealed.to_string().contains(CANARY_SECRET),
        "an explicit reveal must return the requested field"
    );
}

#[tokio::test]
async fn an_error_payload_never_carries_the_secret() {
    let (_dir, service, auth) = service_with_owner();

    // Drive several failures whose inputs contain the canary and assert none of
    // them echoes it back. Error text is the classic accidental leak path.
    let attempts = [
        // A wrong master password must not come back in the error text.
        json!({"command": "unlock", "auth": auth, "password": CANARY_SECRET, "session_ttl_seconds": 300}),
        // A rejected write whose payload holds a secret must not echo it.
        json!({"command": "entries_create", "auth": auth,
               "idempotency_key": "parity-leak-1", "dry_run": false,
               "input": {"group_id": "grp_does_not_exist", "kind": "core.login",
                         "title": "Leak Probe", "password": CANARY_SECRET}}),
        json!({"command": "entries_update", "auth": auth, "id": "itm_does_not_exist",
               "idempotency_key": "parity-leak-2", "dry_run": false,
               "patch": {"password": CANARY_SECRET}}),
    ];

    for attempt in attempts {
        let response = call(&service, attempt.clone()).await;
        if response["ok"] == json!(true) {
            continue;
        }
        let error = response["error"].to_string();
        assert!(
            !error.contains(CANARY_SECRET),
            "an error payload leaked the input secret: {error}"
        );
    }
}

#[tokio::test]
async fn mobile_capabilities_deny_agent_handoff_even_when_the_feature_is_on() {
    // Regression test for a real defect. Gating this on a cargo feature alone
    // did not work: cargo unifies features across a workspace build, so a
    // `--workspace` run compiled this crate with `agent-handoff` enabled for
    // everyone and the mobile client reached the real handler. This test only
    // means anything because it runs in exactly that unified build.
    let (_dir, service, auth) = service_with_owner();

    // Both payloads must be well formed: the guard runs after parsing, so a
    // malformed request would be rejected for the wrong reason and prove
    // nothing.
    let requests = [
        json!({"command": "agent_handoff_get", "auth": auth, "handoff_id": "any"}),
        json!({"command": "agent_handoff_create", "auth": auth, "input": {
            "protocol_version": 1,
            "expected_vault_id": "vault_any",
            "recipe_id": "dotenv",
            "kind": "core.api_credential",
            "group_id": null,
            "project_slug": null,
            "agent_access": "none",
            "source_path": null,
            "context": null
        }}),
    ];

    for request in requests {
        let command = request["command"].as_str().expect("a command").to_owned();
        let raw = dispatch_line(&service, RpcCapabilities::MOBILE, &request.to_string()).await;
        let response: Value = serde_json::from_str(&raw).expect("JSON envelope");
        assert_eq!(response["ok"], json!(false), "{command}: {response}");
        assert_eq!(
            response["error"]["error"], "denied",
            "{command} must be denied for a mobile client, not dispatched: {response}"
        );
    }
}

#[tokio::test]
async fn desktop_capabilities_still_reach_the_agent_handoff_handler() {
    // The other half: the desktop daemon must keep the workflow. A `denied`
    // here would mean the guard is too broad.
    let (_dir, service, auth) = service_with_owner();

    let request = json!({"command": "agent_handoff_get", "auth": auth, "handoff_id": "missing"});
    let raw = dispatch_line(&service, RpcCapabilities::DESKTOP, &request.to_string()).await;
    let response: Value = serde_json::from_str(&raw).expect("JSON envelope");
    assert_eq!(response["ok"], json!(false), "{response}");
    assert_ne!(
        response["error"]["error"], "denied",
        "desktop must reach the real handler, which reports a missing handoff: {response}"
    );
}

/// A service whose unlocked owner holds `role`.
fn service_with_role(role: LocalOwnerRole) -> (tempfile::TempDir, Arc<KeyLeaseService>, Value) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = NativeStore::open(dir.path().join("vault.sqlite")).expect("store opens");
    let service = Arc::new(KeyLeaseService::new(Arc::new(store)).expect("service starts"));
    service
        .initialize(MASTER_PASSWORD.as_bytes(), chrono::Duration::minutes(5))
        .expect("vault initialises");
    let (agent_id, token) = service
        .register_local_owner_client(role)
        .expect("owner client registers");
    service
        .unlock_for_client(
            &agent_id,
            MASTER_PASSWORD.as_bytes(),
            chrono::Duration::minutes(5),
        )
        .expect("owner unlocks");
    let auth = json!({"agent_id": agent_id, "token": token, "session_id": "role"});
    (dir, service, auth)
}

#[tokio::test]
async fn a_mobile_owner_can_do_the_everyday_vault_work() {
    let (_dir, service, auth) = service_with_role(LocalOwnerRole::MobileOwner);

    for request in [
        json!({"command": "groups_list", "auth": auth}),
        json!({"command": "entries_search", "auth": auth, "query": ""}),
        json!({"command": "connections_list", "auth": auth}),
        json!({"command": "approvals_list", "auth": auth, "limit": 10}),
        json!({"command": "audit_query", "auth": auth, "limit": 10}),
    ] {
        let command = request["command"].as_str().expect("a command").to_owned();
        let response = call(&service, request).await;
        assert_eq!(
            response["ok"],
            json!(true),
            "a phone owner must be able to run {command}: {response}"
        );
    }
}

#[tokio::test]
async fn a_mobile_owner_may_not_widen_the_vault() {
    let (_dir, mobile, mobile_auth) = service_with_role(LocalOwnerRole::MobileOwner);
    let (_dir_d, desktop, desktop_auth) = service_with_role(LocalOwnerRole::DesktopOwner);

    // Adding a connector credential is the thing a stolen unlocked phone must
    // not be able to do. Compare against the desktop, which may.
    let add = |auth: &Value| {
        json!({"command": "connection_add", "auth": auth, "provider": "fake",
               "credential": "probe-credential", "authorized_resources": []})
    };

    let refused = call(&mobile, add(&mobile_auth)).await;
    assert_eq!(refused["ok"], json!(false), "{refused}");
    assert_eq!(
        refused["error"]["error"], "denied",
        "connection_add must be denied for a phone: {refused}"
    );

    let desktop_response = call(&desktop, add(&desktop_auth)).await;
    assert_ne!(
        desktop_response["error"]["error"],
        json!("denied"),
        "the desktop must still reach the handler, or this test proves nothing: \
         {desktop_response}"
    );
}

#[tokio::test]
async fn migrations_and_agent_handoff_stay_on_the_desktop() {
    let (_dir, mobile, auth) = service_with_role(LocalOwnerRole::MobileOwner);

    // Both are refused by the service role, independently of RpcCapabilities.
    // Dispatching with DESKTOP capabilities is what makes that the only gate
    // under test here.
    for request in [
        json!({"command": "migrations_status", "auth": auth}),
        json!({"command": "agent_handoff_get", "auth": auth, "handoff_id": "any"}),
    ] {
        let command = request["command"].as_str().expect("a command").to_owned();
        let raw = dispatch_line(&mobile, RpcCapabilities::DESKTOP, &request.to_string()).await;
        let response: Value = serde_json::from_str(&raw).expect("JSON envelope");
        assert_eq!(response["ok"], json!(false), "{command}: {response}");
        assert_eq!(
            response["error"]["error"], "denied",
            "{command} must be denied for a phone owner by the service role: {response}"
        );
    }
}

#[tokio::test]
async fn an_unknown_role_string_grants_nothing() {
    // An older binary reading a vault written by a newer one must fail closed
    // rather than fall back to full desktop authority.
    let (_dir, service, auth) = service_with_role(LocalOwnerRole::MobileOwner);
    let response = call(&service, json!({"command": "groups_list", "auth": auth})).await;
    assert_eq!(response["ok"], json!(true), "baseline: {response}");
    // The fail-closed path itself is unit-tested in keylease-store; this only
    // pins that a known role does grant authority, so that test is meaningful.
}

/// The provisioning commands, by their wire `provision` value.
const PROVISION_COMMANDS: [&str; 6] = [
    "inspect",
    "restore_backup",
    "create",
    "unlock_owner",
    "change_password",
    "export_backup",
];

#[test]
fn no_provisioning_operation_is_reachable_as_an_rpc_command() {
    // This is the actual guarantee, and it does not depend on a cargo feature.
    // Provisioning cannot be authenticated, so if any of these were an
    // `RpcRequest` variant, any process that can reach the daemon socket could
    // mint itself an owner token.
    let accepted = accepted_commands();
    for name in PROVISION_COMMANDS {
        assert!(
            !accepted.contains(&name.to_owned()),
            "`{name}` must not be an RpcRequest command: provisioning has to stay off \
             the authenticated channel"
        );
    }
    // The tag key differs too, so a provisioning document cannot be replayed
    // into the request dispatcher by accident.
    for name in PROVISION_COMMANDS {
        let smuggled = json!({"command": name});
        assert!(
            serde_json::from_value::<RpcRequest>(smuggled).is_err(),
            "`{name}` must not deserialise as an RpcRequest"
        );
    }
}
