//! Cloud relay (ADR 0006): stores members' public keys, forwards sealed
//! messages between the owner and nodes, and keeps the latest sealed backup of
//! each member's items. It holds no key that opens a payload. Requests other
//! than account creation, invite lookup, joining and recovery are signed with
//! the member's Ed25519 key.

use crate::api::{ApiError, ApiResult, CloudApiState, authorize};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, Method},
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use keylease_core::{
    KeyLeaseError,
    relay::{
        CreateRelayAccount, CreateRelayInvite, FetchRecoveryKit, HEADER_MEMBER, HEADER_SIGNATURE,
        HEADER_TIMESTAMP, JoinRelay, RELAY_MAX_SEALED_BYTES, RELAY_REQUEST_SKEW_SECONDS,
        RecoveryKitResponse, RelayAccountCreated, RelayAck, RelayBackup, RelayBackupList,
        RelayEnvelope, RelayInbox, RelayInvite, RelayJoined, RelayMember, RelayMemberKeys,
        RelayRole, kind, relay_digest, relay_request_signing_input,
    },
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::Row;
use subtle::ConstantTimeEq;

/// Undelivered messages a mailbox may hold.
const MAX_MAILBOX: i64 = 10_000;
/// Backup objects one member may keep.
const MAX_BACKUPS: i64 = 50_000;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/relay/accounts", post(create_account))
        .route("/v1/relay/recovery", post(fetch_recovery))
        .route("/v1/relay/invites", post(create_invite))
        .route("/v1/relay/invites/{lookup}", get(get_invite))
        .route("/v1/relay/join", post(join))
        .route("/v1/relay/members", get(list_members))
        .route("/v1/relay/members/{member}", delete(revoke_member))
        .route("/v1/relay/messages", post(send_message).get(inbox))
        .route("/v1/relay/messages/ack", post(ack))
        .route("/v1/relay/backups", put(put_backup).get(list_backups))
}

fn invalid(reason: impl Into<String>) -> ApiError {
    ApiError(KeyLeaseError::InvalidRequest {
        reason: reason.into(),
    })
}
fn denied(reason: impl Into<String>) -> ApiError {
    ApiError(KeyLeaseError::Denied {
        reason: reason.into(),
    })
}
fn storage(_: sqlx::Error) -> ApiError {
    ApiError(KeyLeaseError::Storage)
}
fn parse<T: DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|_| invalid("malformed relay request"))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn valid_hex_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 64 && !value.chars().any(char::is_control)
}
fn key_bytes(value: &str) -> Option<[u8; 32]> {
    STANDARD
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
}
fn valid_keys(keys: &RelayMemberKeys) -> bool {
    key_bytes(&keys.sign_public_b64)
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .is_some()
        && key_bytes(&keys.box_public_b64).is_some()
}
fn valid_tag(value: &str) -> bool {
    STANDARD
        .decode(value)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

/// The authenticated member of a signed request.
struct Caller {
    member_id: String,
    account_id: String,
    role: RelayRole,
}

fn role_of(value: &str) -> RelayRole {
    if value == "owner" {
        RelayRole::Owner
    } else {
        RelayRole::Node
    }
}

async fn verify(
    state: &CloudApiState,
    method: &Method,
    uri: &OriginalUri,
    headers: &HeaderMap,
    body: &[u8],
) -> ApiResult<Caller> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| denied("missing relay signature"))
    };
    let member_id = header(HEADER_MEMBER)?;
    let timestamp: i64 = header(HEADER_TIMESTAMP)?
        .parse()
        .map_err(|_| denied("invalid relay timestamp"))?;
    if (Utc::now().timestamp() - timestamp).abs() > RELAY_REQUEST_SKEW_SECONDS {
        return Err(denied("relay request is stale; check the clock"));
    }
    let signature: [u8; 64] = STANDARD
        .decode(header(HEADER_SIGNATURE)?)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| denied("invalid relay signature"))?;
    let row = sqlx::query(
        "SELECT account_id,role,sign_public_b64 FROM relay_members WHERE member_id=$1 AND revoked_at IS NULL",
    )
    .bind(member_id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("invalid relay signature"))?;
    let public: String = row.get("sign_public_b64");
    let key = key_bytes(&public)
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or(ApiError(KeyLeaseError::Storage))?;
    let path = uri.0.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    key.verify(
        &relay_request_signing_input(method.as_str(), path, timestamp, body),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| denied("invalid relay signature"))?;
    Ok(Caller {
        member_id: member_id.to_owned(),
        account_id: row.get("account_id"),
        role: role_of(row.get::<String, _>("role").as_str()),
    })
}

fn new_member_id() -> String {
    format!("member_{}", uuid::Uuid::now_v7().simple())
}

async fn create_account(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateRelayAccount>,
) -> ApiResult<Json<RelayAccountCreated>> {
    authorize(&state, &headers)?;
    if !valid_id(&body.account_id)
        || !valid_name(&body.owner_name)
        || !valid_keys(&body.owner)
        || !valid_hex_hash(&body.recovery_lookup_hash)
        || body.recovery_kit.is_empty()
        || body.recovery_kit.len() > 16 * 1024
    {
        return Err(invalid("invalid relay account"));
    }
    let member_id = new_member_id();
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    let inserted = sqlx::query(
        "INSERT INTO relay_accounts(account_id,owner_member_id,recovery_lookup_hash,recovery_kit,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(&body.account_id)
    .bind(&member_id)
    .bind(&body.recovery_lookup_hash)
    .bind(&body.recovery_kit)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    if inserted.rows_affected() != 1 {
        return Err(denied("relay account already exists"));
    }
    sqlx::query(
        "INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,created_at) VALUES($1,$2,'owner',$3,$4,$5,$6)",
    )
    .bind(&member_id)
    .bind(&body.account_id)
    .bind(body.owner_name.trim())
    .bind(&body.owner.sign_public_b64)
    .bind(&body.owner.box_public_b64)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await
    .map_err(|_| invalid("relay keys are already registered"))?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(RelayAccountCreated {
        account_id: body.account_id,
        owner_member_id: member_id,
    }))
}

async fn fetch_recovery(
    State(state): State<CloudApiState>,
    Json(body): Json<FetchRecoveryKit>,
) -> ApiResult<Json<RecoveryKitResponse>> {
    let not_found = || {
        ApiError(KeyLeaseError::NotFound {
            resource: "recovery kit".into(),
        })
    };
    let lookup = (0..body.lookup_hex.len())
        .step_by(2)
        .map(|i| {
            body.lookup_hex
                .get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| invalid("invalid recovery lookup"))?;
    let row = sqlx::query(
        "SELECT owner_member_id,recovery_lookup_hash,recovery_kit FROM relay_accounts WHERE account_id=$1",
    )
    .bind(&body.account_id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(not_found)?;
    let stored: String = row.get("recovery_lookup_hash");
    if !bool::from(relay_digest(&lookup).as_bytes().ct_eq(stored.as_bytes())) {
        return Err(not_found());
    }
    Ok(Json(RecoveryKitResponse {
        account_id: body.account_id,
        owner_member_id: row.get("owner_member_id"),
        recovery_kit: row.get("recovery_kit"),
    }))
}

async fn create_invite(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    if caller.role != RelayRole::Owner {
        return Err(denied("only the owner creates invites"));
    }
    let invite: CreateRelayInvite = parse(&body)?;
    let ttl = invite.expires_at - Utc::now();
    if !valid_hex_hash(&invite.lookup_hash)
        || !valid_name(&invite.name)
        || !valid_tag(&invite.owner_tag_b64)
        || ttl <= chrono::Duration::zero()
        || ttl > chrono::Duration::hours(24)
    {
        return Err(invalid("invalid relay invite"));
    }
    sqlx::query(
        "INSERT INTO relay_invites(lookup_hash,account_id,name,owner_tag_b64,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(&invite.lookup_hash)
    .bind(&caller.account_id)
    .bind(invite.name.trim())
    .bind(&invite.owner_tag_b64)
    .bind(invite.expires_at)
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({"created": true})))
}

async fn open_invite(state: &CloudApiState, lookup: &str) -> ApiResult<(String, RelayInvite)> {
    let hash = relay_digest(lookup.trim().to_ascii_uppercase().as_bytes());
    let row = sqlx::query(
        "SELECT i.account_id,i.name,i.owner_tag_b64,i.expires_at,a.owner_member_id,m.sign_public_b64,m.box_public_b64 \
         FROM relay_invites i JOIN relay_accounts a ON a.account_id=i.account_id \
         JOIN relay_members m ON m.member_id=a.owner_member_id \
         WHERE i.lookup_hash=$1 AND i.used_at IS NULL AND i.expires_at > $2",
    )
    .bind(&hash)
    .bind(Utc::now())
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| {
        ApiError(KeyLeaseError::NotFound {
            resource: "invite (expired, used or mistyped)".into(),
        })
    })?;
    Ok((
        hash,
        RelayInvite {
            account_id: row.get("account_id"),
            owner_member_id: row.get("owner_member_id"),
            owner: RelayMemberKeys {
                sign_public_b64: row.get("sign_public_b64"),
                box_public_b64: row.get("box_public_b64"),
            },
            name: row.get("name"),
            owner_tag_b64: row.get("owner_tag_b64"),
            expires_at: row.get::<DateTime<Utc>, _>("expires_at"),
        },
    ))
}

async fn get_invite(
    State(state): State<CloudApiState>,
    Path(lookup): Path<String>,
) -> ApiResult<Json<RelayInvite>> {
    Ok(Json(open_invite(&state, &lookup).await?.1))
}

async fn join(
    State(state): State<CloudApiState>,
    Json(body): Json<JoinRelay>,
) -> ApiResult<Json<RelayJoined>> {
    if !valid_keys(&body.keys) || !valid_tag(&body.node_tag_b64) {
        return Err(invalid("invalid node keys"));
    }
    let (hash, invite) = open_invite(&state, &body.lookup).await?;
    let member_id = new_member_id();
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    let used =
        sqlx::query("UPDATE relay_invites SET used_at=$2 WHERE lookup_hash=$1 AND used_at IS NULL")
            .bind(&hash)
            .bind(Utc::now())
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
    if used.rows_affected() != 1 {
        return Err(denied("invite was already used"));
    }
    sqlx::query(
        "INSERT INTO relay_members(member_id,account_id,role,name,sign_public_b64,box_public_b64,node_tag_b64,invite_lookup_hash,created_at) VALUES($1,$2,'node',$3,$4,$5,$6,$7,$8)",
    )
    .bind(&member_id)
    .bind(&invite.account_id)
    .bind(&invite.name)
    .bind(&body.keys.sign_public_b64)
    .bind(&body.keys.box_public_b64)
    .bind(&body.node_tag_b64)
    .bind(&hash)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await
    .map_err(|_| invalid("relay keys are already registered"))?;
    tx.commit().await.map_err(storage)?;
    Ok(Json(RelayJoined {
        account_id: invite.account_id,
        member_id,
    }))
}

fn member_from_row(row: &sqlx::postgres::PgRow) -> RelayMember {
    RelayMember {
        member_id: row.get("member_id"),
        role: role_of(row.get::<String, _>("role").as_str()),
        name: row.get("name"),
        keys: RelayMemberKeys {
            sign_public_b64: row.get("sign_public_b64"),
            box_public_b64: row.get("box_public_b64"),
        },
        node_tag_b64: row.get("node_tag_b64"),
        invite_lookup_hash: row.get("invite_lookup_hash"),
        created_at: row.get("created_at"),
        revoked_at: row.get("revoked_at"),
    }
}

async fn list_members(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<RelayMember>>> {
    let caller = verify(&state, &method, &uri, &headers, b"").await?;
    // The owner sees every member; a node sees the owner and itself.
    let rows = sqlx::query(
        "SELECT * FROM relay_members WHERE account_id=$1 AND ($2 OR role='owner' OR member_id=$3) ORDER BY created_at",
    )
    .bind(&caller.account_id)
    .bind(caller.role == RelayRole::Owner)
    .bind(&caller.member_id)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(rows.iter().map(member_from_row).collect()))
}

async fn revoke_member(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    Path(member): Path<String>,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, b"").await?;
    if caller.role != RelayRole::Owner {
        return Err(denied("only the owner removes members"));
    }
    let mut tx = state.repository.pool().begin().await.map_err(storage)?;
    let revoked = sqlx::query(
        "UPDATE relay_members SET revoked_at=COALESCE(revoked_at,$3) WHERE member_id=$1 AND account_id=$2 AND role='node'",
    )
    .bind(&member)
    .bind(&caller.account_id)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    if revoked.rows_affected() != 1 {
        return Err(ApiError(KeyLeaseError::NotFound {
            resource: "node".into(),
        }));
    }
    sqlx::query("DELETE FROM relay_messages WHERE to_member_id=$1")
        .bind(&member)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    // Backups stay: they are what restoring a dead node needs.
    Ok(Json(json!({"revoked": true})))
}

async fn send_message(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let envelope: RelayEnvelope = parse(&body)?;
    if envelope.account_id != caller.account_id || envelope.from_member_id != caller.member_id {
        return Err(denied("a member sends only as itself"));
    }
    if !valid_id(&envelope.message_id)
        || !valid_id(&envelope.object_id)
        || envelope.sealed_json.len() > RELAY_MAX_SEALED_BYTES
        || !STANDARD
            .decode(&envelope.signature_b64)
            .map(|s| s.len() == 64)
            .unwrap_or(false)
    {
        return Err(invalid("invalid relay message"));
    }
    let recipient = sqlx::query(
        "SELECT role FROM relay_members WHERE member_id=$1 AND account_id=$2 AND revoked_at IS NULL",
    )
    .bind(&envelope.to_member_id)
    .bind(&caller.account_id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| {
        ApiError(KeyLeaseError::NotFound {
            resource: "recipient".into(),
        })
    })?;
    let recipient_role = role_of(recipient.get::<String, _>("role").as_str());
    let allowed = match (caller.role, recipient_role) {
        (RelayRole::Owner, RelayRole::Node) => {
            kind::OWNER_TO_NODE.contains(&envelope.kind.as_str())
        }
        (RelayRole::Node, RelayRole::Owner) => {
            kind::NODE_TO_OWNER.contains(&envelope.kind.as_str())
        }
        _ => false,
    };
    if !allowed {
        return Err(denied("this message kind is not allowed in this direction"));
    }
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM relay_messages WHERE to_member_id=$1")
            .bind(&envelope.to_member_id)
            .fetch_one(state.repository.pool())
            .await
            .map_err(storage)?;
    if pending >= MAX_MAILBOX {
        return Err(denied("the recipient's mailbox is full"));
    }
    let json = serde_json::to_string(&envelope).map_err(|_| ApiError(KeyLeaseError::Storage))?;
    // Re-sending a message id is a no-op, so a retried sync never duplicates.
    sqlx::query(
        "INSERT INTO relay_messages(message_id,account_id,to_member_id,envelope_json,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind(&envelope.message_id)
    .bind(&caller.account_id)
    .bind(&envelope.to_member_id)
    .bind(json)
    .bind(Utc::now())
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({"accepted": true})))
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    200
}

async fn inbox(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    Query(query): Query<LimitQuery>,
) -> ApiResult<Json<RelayInbox>> {
    let caller = verify(&state, &method, &uri, &headers, b"").await?;
    let rows = sqlx::query(
        "SELECT envelope_json FROM relay_messages WHERE to_member_id=$1 ORDER BY created_at,message_id LIMIT $2",
    )
    .bind(&caller.member_id)
    .bind(query.limit.clamp(1, 500))
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let messages = rows
        .iter()
        .map(|row| serde_json::from_str(row.get::<&str, _>("envelope_json")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError(KeyLeaseError::Storage))?;
    Ok(Json(RelayInbox { messages }))
}

async fn ack(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let ack: RelayAck = parse(&body)?;
    if ack.message_ids.len() > 500 {
        return Err(invalid("acknowledge at most 500 messages at once"));
    }
    let deleted =
        sqlx::query("DELETE FROM relay_messages WHERE to_member_id=$1 AND message_id = ANY($2)")
            .bind(&caller.member_id)
            .bind(&ack.message_ids)
            .execute(state.repository.pool())
            .await
            .map_err(storage)?;
    Ok(Json(json!({"deleted": deleted.rows_affected()})))
}

async fn put_backup(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let backup: RelayBackup = parse(&body)?;
    if backup.member_id != caller.member_id {
        return Err(denied("a member backs up only its own objects"));
    }
    if !valid_id(&backup.object_id)
        || backup.revision == 0
        || backup.revision > i64::MAX as u64
        || backup.sealed_json.len() > RELAY_MAX_SEALED_BYTES
        || (backup.deleted != backup.sealed_json.is_empty())
        || !STANDARD
            .decode(&backup.signature_b64)
            .map(|s| s.len() == 64)
            .unwrap_or(false)
    {
        return Err(invalid("invalid relay backup"));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_backups WHERE member_id=$1")
        .bind(&caller.member_id)
        .fetch_one(state.repository.pool())
        .await
        .map_err(storage)?;
    if count >= MAX_BACKUPS {
        return Err(denied("backup quota reached"));
    }
    // Only a newer revision replaces a stored one, so a stale retry is a no-op.
    let stored = sqlx::query(
        "INSERT INTO relay_backups(member_id,object_id,account_id,revision,deleted,sealed_json,signature_b64,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(member_id,object_id) DO UPDATE SET \
         revision=excluded.revision,deleted=excluded.deleted,sealed_json=excluded.sealed_json,\
         signature_b64=excluded.signature_b64,updated_at=excluded.updated_at \
         WHERE relay_backups.revision < excluded.revision",
    )
    .bind(&caller.member_id)
    .bind(&backup.object_id)
    .bind(&caller.account_id)
    .bind(backup.revision as i64)
    .bind(backup.deleted)
    .bind(&backup.sealed_json)
    .bind(&backup.signature_b64)
    .bind(Utc::now())
    .execute(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(json!({"stored": stored.rows_affected() == 1})))
}

#[derive(Debug, Deserialize)]
struct BackupQuery {
    member: String,
}

async fn list_backups(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    Query(query): Query<BackupQuery>,
) -> ApiResult<Json<RelayBackupList>> {
    let caller = verify(&state, &method, &uri, &headers, b"").await?;
    if caller.role != RelayRole::Owner {
        return Err(denied("only the owner reads backups"));
    }
    let rows = sqlx::query(
        "SELECT member_id,object_id,revision,deleted,sealed_json,signature_b64,updated_at FROM relay_backups WHERE account_id=$1 AND member_id=$2 ORDER BY object_id",
    )
    .bind(&caller.account_id)
    .bind(&query.member)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(Json(RelayBackupList {
        backups: rows
            .iter()
            .map(|row| RelayBackup {
                member_id: row.get("member_id"),
                object_id: row.get("object_id"),
                revision: row.get::<i64, _>("revision") as u64,
                deleted: row.get("deleted"),
                sealed_json: row.get("sealed_json"),
                signature_b64: row.get("signature_b64"),
                updated_at: row.get("updated_at"),
            })
            .collect(),
    }))
}
