//! The on-device vault lifecycle, over the FFI.
//!
//! These run entirely on the host; see `tests/ffi.rs` for why that matters.

use std::ptr;

use keylease_mobile::{
    NO_HANDLE, STATUS_OK, keylease_call, keylease_close, keylease_free, keylease_open,
    keylease_provision,
};
use serde_json::{Value, json};

const MASTER_PASSWORD: &str = "provision-master-password-4a19";
const CANARY_SECRET: &str = "provision-canary-6d20-secret";

fn take(out: *mut u8, len: usize) -> Value {
    assert!(!out.is_null(), "a response buffer was expected");
    let text = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
    unsafe { keylease_free(out, len) };
    serde_json::from_slice(&text).expect("the response is always JSON")
}

fn open(path: &str) -> u64 {
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let handle = unsafe { keylease_open(path.as_ptr(), path.len(), &mut out, &mut len) };
    let body = take(out, len);
    assert_ne!(handle, NO_HANDLE, "open failed: {body}");
    handle
}

fn provision(handle: u64, request: &Value) -> Value {
    let body = request.to_string();
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let status =
        unsafe { keylease_provision(handle, body.as_ptr(), body.len(), &mut out, &mut len) };
    assert_eq!(status, STATUS_OK);
    take(out, len)
}

fn call(handle: u64, request: &Value) -> Value {
    let body = request.to_string();
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let status = unsafe { keylease_call(handle, body.as_ptr(), body.len(), &mut out, &mut len) };
    assert_eq!(status, STATUS_OK);
    take(out, len)
}

#[test]
fn a_standalone_vault_can_be_created_and_used() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault.sqlite");
    let handle = open(path.to_str().expect("utf-8"));

    let created = provision(
        handle,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );
    assert_eq!(created["ok"], json!(true), "{created}");
    assert_eq!(
        created["result"]["provenance"], "created_locally",
        "provenance must be recorded so a future sync engine can refuse to \
         enrol an unmergeable vault: {created}"
    );
    let auth = json!({
        "agent_id": created["result"]["agent_id"],
        "token": created["result"]["token"],
        "session_id": "provision",
    });

    // The default group and the mobile owner rule are both in place.
    let groups = call(handle, &json!({"command": "groups_list", "auth": auth}));
    assert_eq!(groups["ok"], json!(true), "{groups}");
    assert!(
        !groups["result"].as_array().expect("groups").is_empty(),
        "a new vault gets a starting group: {groups}"
    );

    keylease_close(handle);
}

#[test]
fn creating_a_standalone_vault_requires_acknowledgement() {
    let dir = tempfile::tempdir().expect("temp dir");
    let handle = open(dir.path().join("vault.sqlite").to_str().expect("utf-8"));

    // `initialize` mints a random account root key, so this vault could never
    // be merged with the user's desktop. That is not recoverable, so it must
    // not happen by accident.
    let refused = provision(
        handle,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": false}),
    );
    assert_eq!(refused["ok"], json!(false), "{refused}");
    assert_eq!(refused["error"]["error"], "invalid_request", "{refused}");

    keylease_close(handle);
}

#[test]
fn the_phone_gets_mobile_authority_not_desktop_authority() {
    let dir = tempfile::tempdir().expect("temp dir");
    let handle = open(dir.path().join("vault.sqlite").to_str().expect("utf-8"));
    let created = provision(
        handle,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );
    let auth = json!({
        "agent_id": created["result"]["agent_id"],
        "token": created["result"]["token"],
        "session_id": "provision",
    });
    assert_eq!(
        created["result"]["agent_id"], "agent_mobile",
        "a phone must not present itself as the desktop: {created}"
    );

    // Everyday work is allowed.
    assert_eq!(
        call(
            handle,
            &json!({"command": "connections_list", "auth": auth})
        )["ok"],
        json!(true)
    );

    // Widening the vault is not.
    let refused = call(
        handle,
        &json!({"command": "connection_add", "auth": auth, "provider": "fake",
                "credential": "probe", "authorized_resources": []}),
    );
    assert_eq!(refused["error"]["error"], "denied", "{refused}");

    keylease_close(handle);
}

#[test]
fn a_backup_round_trips_onto_a_second_device_and_keeps_the_vault_identity() {
    // This is the path a phone should normally take, and the reason it matters
    // is key identity: a restored vault shares the account root key, so the two
    // devices could later sync. A created one never could.
    let source_dir = tempfile::tempdir().expect("temp dir");
    let source = open(
        source_dir
            .path()
            .join("vault.sqlite")
            .to_str()
            .expect("utf-8"),
    );
    let created = provision(
        source,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );
    let original_vault_id = created["result"]["vault_id"].clone();
    let source_auth = json!({
        "agent_id": created["result"]["agent_id"],
        "token": created["result"]["token"],
        "session_id": "provision",
    });

    let groups = call(
        source,
        &json!({"command": "groups_list", "auth": source_auth}),
    );
    let group_id = groups["result"][0]["id"]
        .as_str()
        .expect("a group")
        .to_owned();
    let entry = call(
        source,
        &json!({"command": "entries_create", "auth": source_auth,
                "idempotency_key": "backup-entry", "dry_run": false,
                "input": {"group_id": group_id, "kind": "core.login",
                          "title": "Backup Entry", "password": CANARY_SECRET}}),
    );
    assert_eq!(entry["ok"], json!(true), "{entry}");

    let backup_path = source_dir.path().join("vault.backup");
    let exported = provision(
        source,
        &json!({"provision": "export_backup",
                "destination_path": backup_path.to_str().expect("utf-8")}),
    );
    assert_eq!(exported["ok"], json!(true), "{exported}");
    assert_eq!(
        exported["result"]["includes_connections"],
        json!(false),
        "a mobile export must leave connector credentials behind by default: {exported}"
    );
    keylease_close(source);

    // A second device adopts it.
    let target_dir = tempfile::tempdir().expect("temp dir");
    let target = open(
        target_dir
            .path()
            .join("vault.sqlite")
            .to_str()
            .expect("utf-8"),
    );
    let restored = provision(
        target,
        &json!({"provision": "restore_backup",
                "source_path": backup_path.to_str().expect("utf-8"),
                "password": MASTER_PASSWORD, "session_ttl_seconds": 300}),
    );
    assert_eq!(restored["ok"], json!(true), "{restored}");
    assert_eq!(restored["result"]["provenance"], "restored", "{restored}");
    assert_eq!(
        restored["result"]["vault_id"], original_vault_id,
        "a restored vault must keep its identity, or the two devices can never sync"
    );

    let target_auth = json!({
        "agent_id": restored["result"]["agent_id"],
        "token": restored["result"]["token"],
        "session_id": "provision",
    });
    let found = call(
        target,
        &json!({"command": "entries_search", "auth": target_auth, "query": "Backup"}),
    );
    assert_eq!(found["ok"], json!(true), "{found}");
    assert!(
        found["result"].as_array().expect("results").len() == 1,
        "the restored vault carries the entry: {found}"
    );

    keylease_close(target);
}

#[test]
fn the_master_password_can_be_rotated_and_the_old_one_stops_working() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault.sqlite");
    let handle = open(path.to_str().expect("utf-8"));
    provision(
        handle,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );

    let wrong = provision(
        handle,
        &json!({"provision": "change_password", "current": "not-the-password",
                "next": "a-brand-new-password"}),
    );
    assert_eq!(
        wrong["ok"],
        json!(false),
        "a wrong current password: {wrong}"
    );

    let short = provision(
        handle,
        &json!({"provision": "change_password", "current": MASTER_PASSWORD, "next": "short"}),
    );
    assert_eq!(short["ok"], json!(false), "a too-short password: {short}");

    let changed = provision(
        handle,
        &json!({"provision": "change_password", "current": MASTER_PASSWORD,
                "next": "a-brand-new-password"}),
    );
    assert_eq!(changed["ok"], json!(true), "{changed}");

    let stale = provision(
        handle,
        &json!({"provision": "unlock_owner", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300}),
    );
    assert_eq!(
        stale["ok"],
        json!(false),
        "the old password must stop working"
    );

    let fresh = provision(
        handle,
        &json!({"provision": "unlock_owner", "password": "a-brand-new-password",
                "session_ttl_seconds": 300}),
    );
    assert_eq!(fresh["ok"], json!(true), "{fresh}");

    keylease_close(handle);
}

#[test]
fn a_provisioning_document_is_not_an_rpc_request_and_vice_versa() {
    let dir = tempfile::tempdir().expect("temp dir");
    let handle = open(dir.path().join("vault.sqlite").to_str().expect("utf-8"));

    // The two channels do not accept each other's documents. This is what keeps
    // unauthenticated provisioning off the authenticated request path.
    let via_call = call(
        handle,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );
    assert_eq!(via_call["ok"], json!(false), "{via_call}");

    let via_provision = provision(handle, &json!({"command": "status"}));
    assert_eq!(via_provision["ok"], json!(false), "{via_provision}");

    keylease_close(handle);
}

#[test]
fn restoring_from_a_missing_or_oversized_file_fails_cleanly() {
    let dir = tempfile::tempdir().expect("temp dir");
    let handle = open(dir.path().join("vault.sqlite").to_str().expect("utf-8"));

    let missing = provision(
        handle,
        &json!({"provision": "restore_backup", "source_path": "/nonexistent-qqqq/backup",
                "password": MASTER_PASSWORD, "session_ttl_seconds": 300}),
    );
    assert_eq!(missing["ok"], json!(false), "{missing}");

    let a_directory = provision(
        handle,
        &json!({"provision": "restore_backup",
                "source_path": dir.path().to_str().expect("utf-8"),
                "password": MASTER_PASSWORD, "session_ttl_seconds": 300}),
    );
    assert_eq!(a_directory["ok"], json!(false), "{a_directory}");

    keylease_close(handle);
}

#[test]
fn a_device_identity_is_minted_once_and_records_provenance() {
    // Reserved before sync exists because SyncMutationEnvelope is signed per
    // device: adding an id later would mean a schema migration plus
    // re-provisioning every device that already made a mutation.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault.sqlite");
    let handle = open(path.to_str().expect("utf-8"));

    let created = provision(
        handle,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );
    let device_id = created["result"]["device_id"]
        .as_str()
        .unwrap_or_else(|| panic!("a device id in {created}"))
        .to_owned();
    assert!(device_id.starts_with("dev_"), "{device_id}");
    assert_eq!(
        created["result"]["provenance"], "created_locally",
        "a standalone vault must be marked unmergeable: {created}"
    );

    // Stable across unlocks, and across closing and reopening the vault.
    let unlocked = provision(
        handle,
        &json!({"provision": "unlock_owner", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300}),
    );
    assert_eq!(unlocked["result"]["device_id"], device_id);
    assert_eq!(
        unlocked["result"]["provenance"], "created_locally",
        "unlocking must not overwrite how the vault came to exist",
    );

    keylease_close(handle);
    let reopened = open(path.to_str().expect("utf-8"));
    let again = provision(
        reopened,
        &json!({"provision": "unlock_owner", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300}),
    );
    assert_eq!(again["result"]["device_id"], device_id);
    keylease_close(reopened);
}

#[test]
fn a_restored_vault_is_marked_mergeable() {
    let source_dir = tempfile::tempdir().expect("temp dir");
    let source = open(
        source_dir
            .path()
            .join("vault.sqlite")
            .to_str()
            .expect("utf-8"),
    );
    let created = provision(
        source,
        &json!({"provision": "create", "password": MASTER_PASSWORD,
                "session_ttl_seconds": 300, "acknowledge_standalone": true}),
    );
    let source_device = created["result"]["device_id"].clone();
    let backup = source_dir.path().join("vault.backup");
    provision(
        source,
        &json!({"provision": "export_backup",
                "destination_path": backup.to_str().expect("utf-8")}),
    );
    keylease_close(source);

    let target_dir = tempfile::tempdir().expect("temp dir");
    let target = open(
        target_dir
            .path()
            .join("vault.sqlite")
            .to_str()
            .expect("utf-8"),
    );
    let restored = provision(
        target,
        &json!({"provision": "restore_backup",
                "source_path": backup.to_str().expect("utf-8"),
                "password": MASTER_PASSWORD, "session_ttl_seconds": 300}),
    );
    assert_eq!(
        restored["result"]["provenance"], "restored",
        "a restored vault shares the account root key and could later sync",
    );
    assert_ne!(
        restored["result"]["device_id"], source_device,
        "each device signs its own sync mutations, so the restored one must \
         mint its own id rather than inherit the source's: {restored}"
    );
    keylease_close(target);
}
