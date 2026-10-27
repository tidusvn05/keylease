//! The in-process transport for the mobile client.
//!
//! On desktop, Flutter is a separate process that reaches the vault over a Unix
//! socket, and `docs/security/threat-model.md` treats it as untrusted. Android
//! has no place to host that daemon, so here the Rust core runs inside the app
//! process and this crate is the boundary Dart calls across.
//!
//! That collapses a process boundary the threat model relies on; see
//! `docs/adr/0004-mobile-in-process-boundary.md`. What replaces it is the
//! Android application sandbox: the vault file lives in app-private storage and
//! only this UID can read it.
//!
//! The surface is deliberately tiny. Requests and responses are the same JSON
//! documents the socket carries, dispatched by the same
//! [`keylease_rpc::dispatch_value`], so the two transports cannot answer the
//! same request differently.
//!
//! # Calling convention
//!
//! Every entry point returns [`STATUS_OK`] or [`STATUS_FATAL`]. `STATUS_FATAL`
//! means no output was produced at all — an allocation failure, a poisoned
//! lock, or a caught panic. Everything else, including every protocol and
//! policy error, arrives as a normal `{"ok":false,...}` envelope in the output
//! buffer, exactly as it would over the socket.
//!
//! Buffers handed back must be released with [`keylease_free`], passing the
//! same length that was written. The length is what makes the deallocation
//! layout provably correct, and getting it wrong is the classic defect in this
//! kind of layer, so `tests/ffi.rs` runs under valgrind.

use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex, Once, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use keylease_rpc::{
    MAX_LOCAL_JSON_BYTES, RpcCapabilities, dispatch_value,
    provisioning::{ProvisionContext, dispatch_provision_line},
};
use keylease_service::KeyLeaseService;
use keylease_store::NativeStore;
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

/// A response buffer was written to the out-parameters.
pub const STATUS_OK: i32 = 0;

/// Nothing was written. The caller has no buffer to free.
pub const STATUS_FATAL: i32 = -1;

/// An invalid handle id. Also what [`keylease_open`] returns on failure.
pub const NO_HANDLE: u64 = 0;

/// One open vault.
///
/// The tokio runtime is per handle rather than global because a handle owns its
/// own connectors and OAuth flows, and closing a vault must be able to tear
/// those down without touching another open vault.
struct SessionHandle {
    runtime: tokio::runtime::Runtime,
    service: Arc<KeyLeaseService>,
    credential: Mutex<Option<MobileCredential>>,
}

/// The current phone-owner credential.
///
/// This never crosses the FFI boundary. Provisioning responses are stripped
/// before they are returned to Dart, and ordinary RPC calls have this block
/// inserted here in Rust.
struct MobileCredential {
    agent_id: String,
    token: Zeroizing<String>,
}

/// Open vaults, addressed by an opaque id.
///
/// This is a table rather than a raw pointer handed to Dart on purpose. A stale
/// or forged pointer would be undefined behaviour in a process holding a
/// decrypted vault; a stale id is just a `not_found` envelope. It is also a
/// table rather than a single global because multi-vault is already a
/// first-class concept on desktop (`keylease desktop vault-switch`).
static SESSIONS: OnceLock<Mutex<HashMap<u64, Arc<SessionHandle>>>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static PANIC_HOOK: Once = Once::new();

fn sessions() -> &'static Mutex<HashMap<u64, Arc<SessionHandle>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Replaces the default panic hook with one that reports location only.
///
/// The default hook formats the panic payload, and on Android its output
/// reaches logcat. A panic carrying a value derived from a secret would print
/// it, which is the "Secret leakage in logs/errors" row of the threat model.
///
/// This is deliberately Android-only. The exposure it defends against is
/// logcat, which does not exist on a host, and installing it everywhere makes
/// every assertion message in the host test suite unreadable — which cost real
/// debugging time before this was scoped down.
#[cfg(target_os = "android")]
fn install_panic_hook() {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            match info.location() {
                Some(at) => eprintln!("keylease-mobile: panic at {}:{}", at.file(), at.line()),
                None => eprintln!("keylease-mobile: panic at an unknown location"),
            }
            // The payload is deliberately dropped, never formatted.
        }));
    });
}

#[cfg(not(target_os = "android"))]
fn install_panic_hook() {
    // Keep the `Once` warm so the two builds stay structurally identical.
    PANIC_HOOK.call_once(|| {});
}

fn envelope_error(code: &str, reason: &str) -> Value {
    json!({"ok": false, "error": {"error": code, "reason": reason}})
}

/// Hands `bytes` to the caller, who must return them to [`keylease_free`].
fn emit(bytes: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return STATUS_FATAL;
    }
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let raw = Box::into_raw(boxed).cast::<u8>();
    // SAFETY: both out-parameters were null-checked immediately above.
    unsafe {
        *out_ptr = raw;
        *out_len = len;
    }
    STATUS_OK
}

fn emit_value(value: Value, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    emit(value.to_string().into_bytes(), out_ptr, out_len)
}

/// Borrows a caller-owned buffer as UTF-8.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes that stay valid for this call.
unsafe fn borrow_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller guarantees the region above.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).ok()
}

/// Rejects database paths a mobile app has no business opening.
///
/// The FUSE check is the load-bearing one. Android's emulated external storage
/// does not implement POSIX advisory locking reliably, and `NativeStore` runs
/// SQLite in WAL mode, so a vault placed there can be corrupted rather than
/// merely slow. The rest is ordinary path hygiene.
fn validate_database_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("the database path is empty".into());
    }
    if trimmed == ":memory:" {
        return Err("an in-memory vault is not a valid mobile database".into());
    }
    let path = Path::new(trimmed);
    if !path.is_absolute() {
        return Err("the database path must be absolute".into());
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("the database path must not contain '..'".into());
    }
    for forbidden in ["/sdcard", "/storage", "/mnt/media_rw"] {
        if path.starts_with(forbidden) {
            return Err(
                "the vault must live in app-private storage; shared storage cannot hold a \
                 WAL-mode SQLite database safely"
                    .into(),
            );
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| "the database path has no parent directory".to_owned())?;
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("the database directory must not be a symlink".into())
        }
        Ok(meta) if !meta.is_dir() => Err("the database parent is not a directory".into()),
        Ok(_) => Ok(path.to_path_buf()),
        Err(_) => Err("the database directory does not exist".into()),
    }
}

fn open_session(database_path: &str) -> Result<(u64, Value), Value> {
    let path = validate_database_path(database_path)
        .map_err(|reason| envelope_error("invalid_request", &reason))?;

    let store = NativeStore::open(&path)
        .map_err(|_| envelope_error("storage", "the vault database could not be opened"))?;
    let service = KeyLeaseService::new(Arc::new(store))
        .map_err(|_| envelope_error("storage", "the vault service could not start"))?;

    // A small multi-thread runtime: connector calls and the Google OAuth
    // loopback listener need a reactor, but the store is a single mutex so
    // there is nothing to gain from more workers.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| envelope_error("storage", "the async runtime could not start"))?;

    let handle = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let session = Arc::new(SessionHandle {
        runtime,
        service: Arc::new(service),
        credential: Mutex::new(None),
    });
    sessions()
        .lock()
        .map_err(|_| envelope_error("storage", "the session table is poisoned"))?
        .insert(handle, session);

    Ok((handle, json!({"ok": true, "result": {"handle": handle}})))
}

fn session(handle: u64) -> Option<Arc<SessionHandle>> {
    sessions().lock().ok()?.get(&handle).cloned()
}

// ---------------------------------------------------------------------------
// Transport-independent cores.
//
// The C ABI (below) and the JNI ABI (`jni` module, for the native Kotlin
// client) are both thin wrappers over these three functions, so the two
// transports cannot answer the same request differently — the same invariant
// `keylease-rpc` keeps between the socket and the C ABI.
// ---------------------------------------------------------------------------

/// Opens `path` and returns its handle id alongside the outcome envelope.
fn open_json(path: &str) -> (u64, Value) {
    match open_session(path) {
        Ok((handle, value)) => (handle, value),
        Err(value) => (NO_HANDLE, value),
    }
}

/// Dispatches one request against an open vault, splicing the owner credential
/// in on the Rust side so it never reaches the caller's heap.
fn call_json(handle: u64, request: &str) -> Value {
    if request.len() > MAX_LOCAL_JSON_BYTES {
        return envelope_error("invalid_request", "the request exceeds the size limit");
    }
    let Some(session) = session(handle) else {
        return envelope_error("not_found", "no vault is open for this handle");
    };
    let Ok(mut parsed) = serde_json::from_str::<Value>(request) else {
        return envelope_error("invalid_request", "the request is not valid JSON");
    };
    let command = parsed.get("command").and_then(Value::as_str);
    if command != Some("status") {
        let credential = match session.credential.lock() {
            Ok(credential) => credential,
            Err(_) => return envelope_error("storage", "the mobile session is unavailable"),
        };
        let Some(credential) = credential.as_ref() else {
            return envelope_error("vault_locked", "unlock the vault to continue");
        };
        let Some(object) = parsed.as_object_mut() else {
            return envelope_error("invalid_request", "the request is not a JSON object");
        };
        // The caller cannot supply or override an owner credential. Keeping
        // this insertion in Rust is the mobile equivalent of the desktop
        // token file boundary.
        object.insert(
            "auth".into(),
            json!({
                "agent_id": credential.agent_id,
                "token": credential.token.as_str(),
                "session_id": "mobile",
            }),
        );
    }
    session.runtime.block_on(dispatch_value(
        &session.service,
        RpcCapabilities::MOBILE,
        parsed,
    ))
}

/// Runs one vault lifecycle operation, keeping the minted owner credential on
/// the Rust side. See [`keylease_provision`] for why this is a separate
/// channel from [`call_json`].
fn provision_json(handle: u64, request: &str) -> Value {
    if request.len() > MAX_LOCAL_JSON_BYTES {
        return envelope_error("invalid_request", "the request exceeds the size limit");
    }
    let Some(session) = session(handle) else {
        return envelope_error("not_found", "no vault is open for this handle");
    };
    let raw = session.runtime.block_on(dispatch_provision_line(
        &session.service,
        ProvisionContext::MOBILE,
        request,
    ));
    let mut response = serde_json::from_str::<Value>(&raw)
        .unwrap_or_else(|_| envelope_error("storage", "the response could not be encoded"));
    if response.get("ok") == Some(&Value::Bool(true)) {
        let result = response.get_mut("result").and_then(Value::as_object_mut);
        if let Some(result) = result {
            let agent_id = result
                .get("agent_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let token = match result.remove("token") {
                Some(Value::String(token)) => Some(Zeroizing::new(token)),
                _ => None,
            };
            if let (Some(agent_id), Some(token)) = (agent_id, token) {
                match session.credential.lock() {
                    Ok(mut credential) => {
                        *credential = Some(MobileCredential { agent_id, token });
                    }
                    Err(_) => {
                        return envelope_error(
                            "storage",
                            "the mobile session could not be established",
                        );
                    }
                }
            }
        }
    }
    response
}

// ---------------------------------------------------------------------------
// The C surface.
// ---------------------------------------------------------------------------

/// Opens the vault at `path` and returns a handle id, or [`NO_HANDLE`].
///
/// A JSON envelope describing the outcome is always written to the out
/// parameters and must be freed with [`keylease_free`].
///
/// # Safety
/// `path_ptr`/`path_len` must describe an initialised UTF-8 region, and
/// `out_ptr`/`out_len` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keylease_open(
    path_ptr: *const u8,
    path_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> u64 {
    install_panic_hook();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: forwarded from this function's own contract.
        let Some(path) = (unsafe { borrow_str(path_ptr, path_len) }) else {
            return (
                NO_HANDLE,
                envelope_error("invalid_request", "the database path is not valid UTF-8"),
            );
        };
        open_json(path)
    }));
    match outcome {
        Ok((handle, value)) => {
            if emit_value(value, out_ptr, out_len) == STATUS_OK {
                handle
            } else {
                // The vault opened but the caller cannot be told; close it
                // rather than leak an unreachable unlocked session.
                if handle != NO_HANDLE {
                    let _ = sessions().lock().map(|mut open| open.remove(&handle));
                }
                NO_HANDLE
            }
        }
        Err(_) => NO_HANDLE,
    }
}

/// Dispatches one request against an open vault.
///
/// The request is the same JSON the socket transport carries, including its
/// `auth` block.
///
/// # Safety
/// `request_ptr`/`request_len` must describe an initialised region, and the out
/// parameters must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keylease_call(
    handle: u64,
    request_ptr: *const u8,
    request_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    install_panic_hook();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: forwarded from this function's own contract.
        let Some(request) = (unsafe { borrow_str(request_ptr, request_len) }) else {
            return envelope_error("invalid_request", "the request is not valid UTF-8");
        };
        call_json(handle, request)
    }));
    match outcome {
        Ok(value) => emit_value(value, out_ptr, out_len),
        Err(_) => STATUS_FATAL,
    }
}

/// Runs one vault lifecycle operation: create, restore, unlock-owner, change
/// password or export a backup.
///
/// This is a separate entry point from [`keylease_call`] on purpose. These
/// operations cannot be authenticated — before they run there is no credential
/// to authenticate with — so they must not be reachable through a channel that
/// carries ordinary requests. No `command` string routes here.
///
/// # Safety
/// `request_ptr`/`request_len` must describe an initialised region, and the out
/// parameters must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keylease_provision(
    handle: u64,
    request_ptr: *const u8,
    request_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    install_panic_hook();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: forwarded from this function's own contract.
        let Some(request) = (unsafe { borrow_str(request_ptr, request_len) }) else {
            return envelope_error("invalid_request", "the request is not valid UTF-8");
        };
        provision_json(handle, request)
    }));
    match outcome {
        Ok(value) => emit_value(value, out_ptr, out_len),
        Err(_) => STATUS_FATAL,
    }
}

/// Locks the vault, zeroising the session keys.
///
/// This deliberately takes no credentials. It is what the Dart lifecycle
/// listener calls when the app goes to the background, and that path must never
/// fail because a token happened to be unavailable.
#[unsafe(no_mangle)]
pub extern "C" fn keylease_lock(handle: u64) -> i32 {
    install_panic_hook();
    catch_unwind(AssertUnwindSafe(|| match session(handle) {
        Some(session) => {
            if let Ok(mut credential) = session.credential.lock() {
                *credential = None;
            }
            let _ = session.service.lock();
            STATUS_OK
        }
        None => STATUS_FATAL,
    }))
    .unwrap_or(STATUS_FATAL)
}

/// Closes the vault and drops its keys.
#[unsafe(no_mangle)]
pub extern "C" fn keylease_close(handle: u64) -> i32 {
    install_panic_hook();
    catch_unwind(AssertUnwindSafe(|| {
        let removed = match sessions().lock() {
            Ok(mut open) => open.remove(&handle),
            Err(_) => return STATUS_FATAL,
        };
        match removed {
            Some(session) => {
                // Lock before dropping so the session keys are zeroised even if
                // another Arc clone is briefly outstanding.
                let _ = session.service.lock();
                drop(session);
                STATUS_OK
            }
            None => STATUS_FATAL,
        }
    }))
    .unwrap_or(STATUS_FATAL)
}

/// Releases a buffer produced by this library, zeroising it first.
///
/// # Safety
/// `ptr` and `len` must be exactly what one of the calls above wrote, and must
/// not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keylease_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: the caller guarantees this is our own allocation of this length,
    // so reconstructing the same boxed slice layout is correct.
    unsafe {
        let slice = ptr::slice_from_raw_parts_mut(ptr, len);
        (*slice).zeroize();
        drop(Box::from_raw(slice));
    }
}

// ---------------------------------------------------------------------------
// The JNI surface.
//
// Built only with `--features jni` for the native Kotlin client in
// `apps/mobile-android`; each symbol name matches that app's
// `ai.leasegate.mobile.bridge.KeyleaseNative` class. Every export is a thin
// adapter over the same
// `open_json`/`call_json`/`provision_json` cores the C ABI uses, so the two
// clients cannot be answered differently. The owner credential is still
// spliced inside `call_json` and `provision_json` — nothing below moves it.
//
// `keylease_free` has no JNI counterpart: a `jstring` is owned by the JVM
// once returned, so there is no caller-managed buffer. That trades the C
// ABI's zeroise-then-free for the ordinary ART string lifecycle — the same
// posture the Dart heap already has, per ADR 0004's accepted residual risk.
// ---------------------------------------------------------------------------

#[cfg(feature = "jni")]
mod jni_bridge {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::{jint, jlong, jstring};

    fn read_string(env: &mut JNIEnv, value: &JString) -> Option<String> {
        env.get_string(value).ok().map(String::from)
    }

    fn write_value(env: &mut JNIEnv, value: Value) -> jstring {
        match env.new_string(value.to_string()) {
            Ok(text) => text.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Opens the vault at `path`. Returns the outcome envelope; the handle id
    /// is inside `result.handle`. Null means no output was produced at all.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_ai_leasegate_mobile_bridge_KeyleaseNative_open(
        mut env: JNIEnv,
        _class: JClass,
        path: JString,
    ) -> jstring {
        install_panic_hook();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let Some(path) = read_string(&mut env, &path) else {
                return envelope_error("invalid_request", "the database path is not valid UTF-8");
            };
            open_json(&path).1
        }));
        match outcome {
            Ok(value) => write_value(&mut env, value),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Dispatches one request. Null means no output was produced at all.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_ai_leasegate_mobile_bridge_KeyleaseNative_call(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        request: JString,
    ) -> jstring {
        install_panic_hook();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let Some(request) = read_string(&mut env, &request) else {
                return envelope_error("invalid_request", "the request is not valid UTF-8");
            };
            call_json(handle as u64, &request)
        }));
        match outcome {
            Ok(value) => write_value(&mut env, value),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Runs one lifecycle operation. Null means no output was produced at all.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_ai_leasegate_mobile_bridge_KeyleaseNative_provision(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        request: JString,
    ) -> jstring {
        install_panic_hook();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let Some(request) = read_string(&mut env, &request) else {
                return envelope_error("invalid_request", "the request is not valid UTF-8");
            };
            provision_json(handle as u64, &request)
        }));
        match outcome {
            Ok(value) => write_value(&mut env, value),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Locks the vault. Same contract as [`keylease_lock`].
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_ai_leasegate_mobile_bridge_KeyleaseNative_lock(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jint {
        keylease_lock(handle as u64)
    }

    /// Closes the vault and drops its keys. Same contract as
    /// [`keylease_close`].
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_ai_leasegate_mobile_bridge_KeyleaseNative_close(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jint {
        keylease_close(handle as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_path_is_refused() {
        assert!(validate_database_path("vault.sqlite").is_err());
    }

    #[test]
    fn shared_storage_is_refused() {
        // WAL plus FUSE advisory locking corrupts rather than fails.
        assert!(validate_database_path("/sdcard/keylease/vault.sqlite").is_err());
        assert!(validate_database_path("/storage/emulated/0/vault.sqlite").is_err());
    }

    #[test]
    fn traversal_and_memory_databases_are_refused() {
        assert!(validate_database_path("/data/data/app/../../vault.sqlite").is_err());
        assert!(validate_database_path(":memory:").is_err());
        assert!(validate_database_path("   ").is_err());
    }

    #[test]
    fn a_real_app_private_path_is_accepted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("vault.sqlite");
        let accepted = validate_database_path(path.to_str().expect("utf-8 path"));
        assert!(accepted.is_ok(), "{accepted:?}");
    }

    #[test]
    fn a_missing_directory_is_refused() {
        assert!(validate_database_path("/nonexistent-abcdef/vault.sqlite").is_err());
    }
}
