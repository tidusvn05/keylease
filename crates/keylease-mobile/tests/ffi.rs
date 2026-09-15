//! Exercises the C surface on the host.
//!
//! This host-target suite carries most of the verification weight for the
//! mobile port: this machine has no `/dev/kvm`, so there is no hardware
//! accelerated emulator and on-device runs are expensive. The `rlib` crate-type
//! is what lets these tests call the `extern "C"` entry points directly.
//!
//! Run under valgrind as well as plain `cargo test`. Mismatched deallocation
//! layout is the dominant defect class here and `cargo test` will not see it:
//!
//! ```sh
//! valgrind --error-exitcode=1 cargo test -p keylease-mobile
//! ```

use std::{ptr, sync::Arc};

use keylease_mobile::{
    NO_HANDLE, STATUS_FATAL, STATUS_OK, keylease_call, keylease_close, keylease_free,
    keylease_lock, keylease_open, keylease_provision,
};
use keylease_service::KeyLeaseService;
use keylease_store::NativeStore;
use serde_json::{Value, json};

const MASTER_PASSWORD: &str = "ffi-master-password-77c1a2";
const CANARY_SECRET: &str = "ffi-canary-93bd10-never-leak";

/// Reads and frees a buffer the library produced.
fn take(out: *mut u8, len: usize) -> Value {
    assert!(!out.is_null(), "a response buffer was expected");
    let text = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
    unsafe { keylease_free(out, len) };
    serde_json::from_slice(&text).expect("the response is always JSON")
}

fn open(path: &str) -> (u64, Value) {
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let handle = unsafe { keylease_open(path.as_ptr(), path.len(), &mut out, &mut len) };
    (handle, take(out, len))
}

fn call(handle: u64, request: &Value) -> (i32, Value) {
    let body = request.to_string();
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let status = unsafe { keylease_call(handle, body.as_ptr(), body.len(), &mut out, &mut len) };
    (status, take(out, len))
}

fn unlock(handle: u64) -> Value {
    let request = json!({"provision": "unlock_owner", "password": MASTER_PASSWORD,
                         "session_ttl_seconds": 300});
    let body = request.to_string();
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let status =
        unsafe { keylease_provision(handle, body.as_ptr(), body.len(), &mut out, &mut len) };
    assert_eq!(status, STATUS_OK);
    take(out, len)
}

/// A vault on disk with an owner client registered, plus that client's auth.
///
/// The vault is prepared through the service directly rather than over the FFI
/// because on-device provisioning is a separate milestone; this suite is about
/// the boundary itself.
fn prepared_vault() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault.sqlite");
    let store = NativeStore::open(&path).expect("store opens");
    let service = Arc::new(KeyLeaseService::new(Arc::new(store)).expect("service starts"));
    service
        .initialize(MASTER_PASSWORD.as_bytes(), chrono::Duration::minutes(5))
        .expect("vault initialises");
    service
        .register_desktop_client()
        .expect("owner client registers");
    // Drop the preparing service so the FFI opens the file cleanly.
    drop(service);
    let path_text = path.to_str().expect("utf-8 path").to_owned();
    (dir, path_text)
}

#[test]
fn a_vault_opens_unlocks_and_closes() {
    let (_dir, path) = prepared_vault();

    let (handle, opened) = open(&path);
    assert_ne!(handle, NO_HANDLE, "open failed: {opened}");
    assert_eq!(opened["ok"], json!(true), "{opened}");

    let (status, body) = call(handle, &json!({"command": "status"}));
    assert_eq!(status, STATUS_OK);
    assert_eq!(body["ok"], json!(true), "{body}");
    assert_eq!(
        body["result"]["locked"],
        json!(true),
        "a freshly opened vault starts locked"
    );

    let unlocked = unlock(handle);
    assert_eq!(unlocked["ok"], json!(true), "{unlocked}");

    let (_, groups) = call(handle, &json!({"command": "groups_list"}));
    assert_eq!(
        groups["ok"],
        json!(true),
        "the owner may list groups: {groups}"
    );

    assert_eq!(keylease_close(handle), STATUS_OK);
}

#[test]
fn locking_takes_effect_and_needs_no_credentials() {
    let (_dir, path) = prepared_vault();
    let (handle, _) = open(&path);

    unlock(handle);

    // No auth block: this is the app-goes-to-background path, which must not be
    // able to fail for want of a token.
    assert_eq!(keylease_lock(handle), STATUS_OK);

    let (_, after) = call(handle, &json!({"command": "groups_list"}));
    assert_eq!(after["ok"], json!(false), "{after}");
    assert_eq!(
        after["error"]["error"], "vault_locked",
        "a locked vault must refuse reads: {after}"
    );

    keylease_close(handle);
}

#[test]
fn a_secret_crosses_the_boundary_only_when_asked_for() {
    let (_dir, path) = prepared_vault();
    let (handle, _) = open(&path);
    unlock(handle);

    let (_, group) = call(
        handle,
        &json!({"command": "groups_create", "name": "Ffi",
                "parent_id": null, "idempotency_key": "ffi-group", "dry_run": false}),
    );
    let group_id = group["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("a group id in {group}"))
        .to_owned();

    let (_, created) = call(
        handle,
        &json!({"command": "entries_create",
                "idempotency_key": "ffi-entry", "dry_run": false,
                "input": {"group_id": group_id, "kind": "core.login",
                          "title": "Ffi Entry", "password": CANARY_SECRET}}),
    );
    assert_eq!(created["ok"], json!(true), "{created}");
    let entry_id = created["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("an entry id in {created}"))
        .to_owned();

    let (_, searched) = call(
        handle,
        &json!({"command": "entries_search", "query": "Ffi"}),
    );
    assert!(
        !searched.to_string().contains(CANARY_SECRET),
        "metadata crossed the boundary carrying the secret"
    );

    let (_, revealed) = call(
        handle,
        &json!({"command": "entries_reveal",
                "id": entry_id, "field": "password"}),
    );
    assert!(
        revealed.to_string().contains(CANARY_SECRET),
        "an explicit reveal must return the field: {revealed}"
    );

    keylease_close(handle);
}

#[test]
fn agent_handoff_is_absent_from_this_build() {
    let (_dir, path) = prepared_vault();
    let (handle, _) = open(&path);
    unlock(handle);

    // The variant still exists in the wire type, so this parses and is then
    // refused, rather than looking like an unknown command.
    let (_, refused) = call(
        handle,
        &json!({"command": "agent_handoff_get", "handoff_id": "any"}),
    );
    assert_eq!(refused["ok"], json!(false), "{refused}");
    assert_eq!(
        refused["error"]["error"], "denied",
        "agent handoff must be denied, not merely unrouted: {refused}"
    );

    keylease_close(handle);
}

#[test]
fn abusive_input_is_refused_without_crashing() {
    let (_dir, path) = prepared_vault();
    let (handle, _) = open(&path);

    // A handle that was never issued.
    let (_, unknown) = call(u64::MAX, &json!({"command": "status"}));
    assert_eq!(unknown["error"]["error"], "not_found", "{unknown}");

    // Non-UTF8 request bytes.
    let mut out: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let bad = [0xffu8, 0xfe, 0xfd];
    let status = unsafe { keylease_call(handle, bad.as_ptr(), bad.len(), &mut out, &mut len) };
    assert_eq!(
        status, STATUS_OK,
        "a bad request is an envelope, not a fatal"
    );
    assert_eq!(take(out, len)["ok"], json!(false));

    // A null request pointer.
    let mut out2: *mut u8 = ptr::null_mut();
    let mut len2: usize = 0;
    let status = unsafe { keylease_call(handle, ptr::null(), 0, &mut out2, &mut len2) };
    assert_eq!(status, STATUS_OK);
    assert_eq!(take(out2, len2)["ok"], json!(false));

    // Well-formed JSON that is not a request.
    let (_, not_a_request) = call(handle, &json!([1, 2, 3]));
    assert_eq!(not_a_request["ok"], json!(false));

    // Freeing null and zero-length is a no-op rather than a crash.
    unsafe { keylease_free(ptr::null_mut(), 0) };
    unsafe { keylease_free(ptr::null_mut(), 16) };

    assert_eq!(keylease_close(handle), STATUS_OK);
    assert_eq!(
        keylease_close(handle),
        STATUS_FATAL,
        "closing twice must report failure, not double free"
    );
    let (_, after_close) = call(handle, &json!({"command": "status"}));
    assert_eq!(after_close["error"]["error"], "not_found", "{after_close}");
}

#[test]
fn a_bad_database_path_is_refused_before_sqlite_sees_it() {
    for path in [
        "/sdcard/keylease/vault.sqlite",
        "relative.sqlite",
        ":memory:",
        "/nonexistent-zzzz/vault.sqlite",
    ] {
        let (handle, body) = open(path);
        assert_eq!(handle, NO_HANDLE, "{path} should not open");
        assert_eq!(body["ok"], json!(false), "{path}: {body}");
    }
}

#[test]
fn two_vaults_stay_independent() {
    let (_dir_a, path_a) = prepared_vault();
    let (_dir_b, path_b) = prepared_vault();

    let (handle_a, _) = open(&path_a);
    let (handle_b, _) = open(&path_b);
    assert_ne!(handle_a, handle_b);

    unlock(handle_a);

    // Unlocking one vault must not unlock the other.
    let (_, b_status) = call(handle_b, &json!({"command": "status"}));
    assert_eq!(b_status["result"]["locked"], json!(true), "{b_status}");

    // A credential held by one handle must never be reused by another.
    let (_, crossed) = call(handle_b, &json!({"command": "groups_list"}));
    assert_eq!(crossed["ok"], json!(false), "{crossed}");
    assert_eq!(crossed["error"]["error"], "vault_locked", "{crossed}");

    keylease_close(handle_a);
    let (_, b_still_open) = call(handle_b, &json!({"command": "status"}));
    assert_eq!(
        b_still_open["ok"],
        json!(true),
        "closing A must not close B"
    );
    keylease_close(handle_b);
}
