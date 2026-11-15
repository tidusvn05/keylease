//! Console approvals and node audit (ADR 0011).
//!
//! A node that turned console approvals on reports its pending approvals
//! every few seconds (`PUT /v1/relay/console/report`, signed with its relay
//! key) and gets back the decisions waiting for it. A person decides in the
//! console: the server builds the decision payload from the node's latest
//! report, the browser signs its challenge with a passkey, and the server
//! checks that signature before queueing the decision. The node checks it
//! again against the passkeys it pinned, so the server only carries
//! decisions. Nodes also upload their audit events, which the console lists.

use crate::api::{ApiResult, CloudApiState};
use crate::console::{require_csrf, session};
use crate::relay::{denied, invalid, parse, storage, verify};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, Method},
    routing::{get, post, put},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use keylease_core::{
    ApprovalRecord, ApprovalState, TrustDecision, TrustDuration,
    console::{
        AccountPasskeys, AuditUpload, ConsoleDecision, DecisionPayload, DecisionResults,
        MAX_AUDIT_UPLOAD, MAX_REPORTED_APPROVALS, NodeReport, NodeReportResponse, PasskeyAssertion,
        PinnedPasskey, decision_challenge,
    },
};
use keylease_crypto::webauthn;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;

/// Audit events kept per node; older ones are dropped.
const AUDIT_KEPT_PER_NODE: i64 = 50_000;
/// A decision not applied within this window is no longer sent.
const DECISION_DELIVERY_MINUTES: i64 = 15;
/// The browser must sign a decision payload within this window.
const PAYLOAD_MAX_AGE_MINUTES: i64 = 5;

pub(crate) fn router() -> Router<CloudApiState> {
    Router::new()
        .route("/v1/relay/console/report", put(node_report))
        .route("/v1/relay/console/results", post(node_results))
        .route(
            "/v1/relay/console/audit",
            get(node_audit_cursor).post(node_audit_upload),
        )
        .route("/v1/relay/console/passkeys", get(node_passkeys))
        .route("/v1/console/approvals", get(list_approvals))
        .route("/v1/console/approvals/challenge", post(decision_options))
        .route("/v1/console/approvals/decide", post(decide))
        .route("/v1/console/audit", get(list_audit))
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

// ---------------------------------------------------------------------------
// Node side (signed with the relay member key)
// ---------------------------------------------------------------------------

async fn node_report(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<NodeReportResponse>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let report: NodeReport = parse(&body)?;
    if report.approvals.len() > MAX_REPORTED_APPROVALS {
        return Err(invalid("too many approvals in one report"));
    }
    let pending: Vec<&ApprovalRecord> = report
        .approvals
        .iter()
        .filter(|approval| approval.state == ApprovalState::Pending)
        .collect();
    let approvals = serde_json::to_value(&pending).map_err(|_| invalid("malformed report"))?;
    let pool = state.repository.pool();
    let previous: Vec<String> = sqlx::query(
        "SELECT jsonb_path_query_array(approvals, '$[*].id') AS ids FROM console_node_reports WHERE member_id=$1",
    )
    .bind(&caller.member_id)
    .fetch_optional(pool)
    .await
    .map_err(storage)?
    .and_then(|row| serde_json::from_value(row.get("ids")).ok())
    .unwrap_or_default();
    let new: Vec<&&ApprovalRecord> = pending
        .iter()
        .filter(|approval| !previous.contains(&approval.id.0))
        .collect();
    if let (Some(first), Some(subject)) = (new.first(), state.console.origin()) {
        let node: Option<String> = sqlx::query("SELECT name FROM relay_members WHERE member_id=$1")
            .bind(&caller.member_id)
            .fetch_optional(pool)
            .await
            .map_err(storage)?
            .map(|row| row.get("name"));
        crate::web_push::notify_account(
            pool.clone(),
            subject.to_owned(),
            caller.account_id.clone(),
            json!({
                "kind": "approval",
                "node": node,
                "count": new.len(),
                "agent": first.agent_id,
                "action": first.action,
            }),
        );
    }
    sqlx::query(
        "INSERT INTO console_node_reports(member_id,account_id,approvals,reported_at) VALUES($1,$2,$3,now()) \
         ON CONFLICT (member_id) DO UPDATE SET approvals=EXCLUDED.approvals, reported_at=now()",
    )
    .bind(&caller.member_id)
    .bind(&caller.account_id)
    .bind(approvals)
    .execute(pool)
    .await
    .map_err(storage)?;
    let rows = sqlx::query(
        "UPDATE console_decisions SET delivered_at=COALESCE(delivered_at, now()) \
         WHERE member_id=$1 AND resolved_at IS NULL AND created_at > $2 \
         RETURNING decision_id,payload,assertion,created_at",
    )
    .bind(&caller.member_id)
    .bind(Utc::now() - Duration::minutes(DECISION_DELIVERY_MINUTES))
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    let mut decisions: Vec<(DateTime<Utc>, ConsoleDecision)> = rows
        .iter()
        .filter_map(|row| {
            let assertion: PasskeyAssertion = serde_json::from_value(row.get("assertion")).ok()?;
            Some((
                row.get("created_at"),
                ConsoleDecision {
                    id: row.get("decision_id"),
                    payload: row.get("payload"),
                    assertion,
                },
            ))
        })
        .collect();
    decisions.sort_by_key(|(created, _)| *created);
    Ok(Json(NodeReportResponse {
        decisions: decisions.into_iter().map(|(_, d)| d).collect(),
    }))
}

async fn node_results(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let results: DecisionResults = parse(&body)?;
    if results.results.len() > 100 {
        return Err(invalid("too many results"));
    }
    let mut updated = 0_u64;
    for result in &results.results {
        if !matches!(result.outcome.as_str(), "approved" | "denied" | "rejected") {
            return Err(invalid("unknown outcome"));
        }
        let reason: Option<String> = result
            .reason
            .as_ref()
            .map(|reason| reason.chars().take(300).collect());
        updated += sqlx::query(
            "UPDATE console_decisions SET outcome=$1, reason=$2, resolved_at=now() \
             WHERE decision_id=$3 AND member_id=$4 AND resolved_at IS NULL",
        )
        .bind(&result.outcome)
        .bind(reason)
        .bind(&result.id)
        .bind(&caller.member_id)
        .execute(state.repository.pool())
        .await
        .map_err(storage)?
        .rows_affected();
    }
    Ok(Json(json!({"updated": updated})))
}

async fn last_audit_seq(state: &CloudApiState, member_id: &str) -> ApiResult<i64> {
    let row = sqlx::query(
        "SELECT COALESCE(MAX(seq), 0) AS seq FROM console_node_audit WHERE member_id=$1",
    )
    .bind(member_id)
    .fetch_one(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(row.get("seq"))
}

/// The last audit sequence number the server has for the calling node.
async fn node_audit_cursor(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let last_seq = last_audit_seq(&state, &caller.member_id).await?;
    Ok(Json(json!({"last_seq": last_seq})))
}

async fn node_audit_upload(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let upload: AuditUpload = parse(&body)?;
    if upload.events.len() > MAX_AUDIT_UPLOAD {
        return Err(invalid("too many audit events in one upload"));
    }
    let pool = state.repository.pool();
    let mut transaction = pool.begin().await.map_err(storage)?;
    for entry in &upload.events {
        if entry.seq <= 0 {
            return Err(invalid("audit sequence numbers start at 1"));
        }
        let event = serde_json::to_value(&entry.event).map_err(|_| invalid("malformed event"))?;
        sqlx::query(
            "INSERT INTO console_node_audit(member_id,seq,account_id,event,occurred_at) VALUES($1,$2,$3,$4,$5) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&caller.member_id)
        .bind(entry.seq)
        .bind(&caller.account_id)
        .bind(event)
        .bind(entry.event.timestamp)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
    }
    sqlx::query(
        "DELETE FROM console_node_audit WHERE member_id=$1 AND seq <= \
         (SELECT seq FROM console_node_audit WHERE member_id=$1 ORDER BY seq DESC OFFSET $2 LIMIT 1)",
    )
    .bind(&caller.member_id)
    .bind(AUDIT_KEPT_PER_NODE)
    .execute(&mut *transaction)
    .await
    .map_err(storage)?;
    transaction.commit().await.map_err(storage)?;
    let last_seq = last_audit_seq(&state, &caller.member_id).await?;
    Ok(Json(
        json!({"stored": upload.events.len(), "last_seq": last_seq}),
    ))
}

async fn account_passkeys(
    state: &CloudApiState,
    account_id: &str,
) -> ApiResult<Vec<PinnedPasskey>> {
    let rows = sqlx::query(
        "SELECT credential_id,public_key_b64,name FROM console_passkeys WHERE account_id=$1 ORDER BY created_at",
    )
    .bind(account_id)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    Ok(rows
        .iter()
        .map(|row| PinnedPasskey {
            credential_id: row.get("credential_id"),
            public_key_b64: row.get("public_key_b64"),
            name: row.get("name"),
        })
        .collect())
}

/// The account's passkeys, for a node to pin.
async fn node_passkeys(
    State(state): State<CloudApiState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<AccountPasskeys>> {
    let caller = verify(&state, &method, &uri, &headers, &body).await?;
    let (rp_id, origin) = state.console.require()?;
    Ok(Json(AccountPasskeys {
        rp_id: rp_id.to_owned(),
        origin: origin.to_owned(),
        passkeys: account_passkeys(&state, &caller.account_id).await?,
    }))
}

// ---------------------------------------------------------------------------
// Console side (session cookie)
// ---------------------------------------------------------------------------

async fn list_approvals(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let account_id = session(&state, &headers).await?;
    let pool = state.repository.pool();
    let nodes = sqlx::query(
        "SELECT r.member_id, m.name, m.role, r.reported_at, r.approvals FROM console_node_reports r \
         JOIN relay_members m ON m.member_id=r.member_id \
         WHERE r.account_id=$1 AND m.revoked_at IS NULL ORDER BY m.name",
    )
    .bind(&account_id)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    let decisions = sqlx::query(
        "SELECT decision_id,member_id,approval_id,approve,passkey_name,created_at,delivered_at,outcome,reason,resolved_at \
         FROM console_decisions WHERE account_id=$1 ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&account_id)
    .fetch_all(pool)
    .await
    .map_err(storage)?;
    Ok(Json(json!({
        "nodes": nodes.iter().map(|row| json!({
            "member_id": row.get::<String, _>("member_id"),
            "name": row.get::<String, _>("name"),
            "role": row.get::<String, _>("role"),
            "reported_at": row.get::<DateTime<Utc>, _>("reported_at"),
            "approvals": row.get::<Value, _>("approvals"),
        })).collect::<Vec<_>>(),
        "decisions": decisions.iter().map(|row| json!({
            "decision_id": row.get::<String, _>("decision_id"),
            "member_id": row.get::<String, _>("member_id"),
            "approval_id": row.get::<String, _>("approval_id"),
            "approve": row.get::<bool, _>("approve"),
            "passkey_name": row.get::<String, _>("passkey_name"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
            "delivered_at": row.get::<Option<DateTime<Utc>>, _>("delivered_at"),
            "outcome": row.get::<Option<String>, _>("outcome"),
            "reason": row.get::<Option<String>, _>("reason"),
            "resolved_at": row.get::<Option<DateTime<Utc>>, _>("resolved_at"),
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionOptions {
    member_id: String,
    approval_id: String,
    approve: bool,
    #[serde(default)]
    trust: Option<TrustDecision>,
}

/// Builds the payload for one decision and the challenge its passkey signs.
async fn decision_options(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let (rp_id, _) = state.console.require()?;
    let request: DecisionOptions = parse(&body)?;
    let trust = request
        .trust
        .filter(|decision| decision.duration != TrustDuration::Once);
    if trust.is_some() && !request.approve {
        return Err(invalid("only an approval can grant trust"));
    }
    let row = sqlx::query(
        "SELECT r.approvals FROM console_node_reports r JOIN relay_members m ON m.member_id=r.member_id \
         WHERE r.member_id=$1 AND r.account_id=$2 AND m.revoked_at IS NULL",
    )
    .bind(&request.member_id)
    .bind(&account_id)
    .fetch_optional(state.repository.pool())
    .await
    .map_err(storage)?
    .ok_or_else(|| invalid("that node has not reported any approvals"))?;
    let approvals: Vec<ApprovalRecord> =
        serde_json::from_value(row.get("approvals")).map_err(|_| invalid("malformed report"))?;
    let approval = approvals
        .iter()
        .find(|approval| approval.id.0 == request.approval_id)
        .ok_or_else(|| invalid("that approval is no longer pending"))?;
    let mut nonce = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let payload = DecisionPayload {
        v: 1,
        account_id: account_id.clone(),
        node: request.member_id,
        approval_id: request.approval_id,
        approve: request.approve,
        request_digest_hex: approval.request_digest_hex.clone(),
        policy_version: approval.policy_version,
        trust,
        issued_at: Utc::now(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
    };
    let payload = serde_json::to_string(&payload).map_err(|_| invalid("malformed payload"))?;
    let passkeys = account_passkeys(&state, &account_id).await?;
    if passkeys.is_empty() {
        return Err(invalid(
            "register a passkey first: decisions are signed with one",
        ));
    }
    Ok(Json(json!({
        "challenge": URL_SAFE_NO_PAD.encode(decision_challenge(&payload)),
        "payload": payload,
        "rp_id": rp_id,
        "allow_credentials": passkeys.iter().map(|p| p.credential_id.clone()).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decide {
    payload: String,
    assertion: PasskeyAssertion,
}

fn b64url(text: &str) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| invalid("invalid passkey response"))
}

/// Checks a passkey-signed decision and queues it for the node.
async fn decide(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    require_csrf(&headers)?;
    let account_id = session(&state, &headers).await?;
    let (rp_id, origin) = state.console.require()?;
    let request: Decide = parse(&body)?;
    let payload: DecisionPayload =
        serde_json::from_str(&request.payload).map_err(|_| invalid("malformed decision"))?;
    let age = Utc::now() - payload.issued_at;
    if payload.v != 1
        || payload.account_id != account_id
        || age > Duration::minutes(PAYLOAD_MAX_AGE_MINUTES)
        || age < Duration::minutes(-1)
    {
        return Err(invalid("the decision expired; decide again"));
    }
    let pool = state.repository.pool();
    let member = sqlx::query(
        "SELECT 1 FROM relay_members WHERE member_id=$1 AND account_id=$2 AND revoked_at IS NULL",
    )
    .bind(&payload.node)
    .bind(&account_id)
    .fetch_optional(pool)
    .await
    .map_err(storage)?;
    if member.is_none() {
        return Err(invalid("unknown node"));
    }
    let credential_id = request
        .assertion
        .credential_id
        .trim_end_matches('=')
        .to_owned();
    let row = sqlx::query(
        "SELECT name,public_key_b64,sign_count FROM console_passkeys WHERE credential_id=$1 AND account_id=$2",
    )
    .bind(&credential_id)
    .bind(&account_id)
    .fetch_optional(pool)
    .await
    .map_err(storage)?
    .ok_or_else(|| denied("unknown passkey"))?;
    let public_key = STANDARD
        .decode(row.get::<String, _>("public_key_b64"))
        .map_err(|_| denied("unknown passkey"))?;
    let stored = u32::try_from(row.get::<i64, _>("sign_count")).unwrap_or(u32::MAX);
    let count = webauthn::verify_assertion(
        &b64url(&request.assertion.client_data_json)?,
        &b64url(&request.assertion.authenticator_data)?,
        &b64url(&request.assertion.signature)?,
        &public_key,
        stored,
        &decision_challenge(&request.payload),
        origin,
        rp_id,
    )
    .map_err(|_| denied("the passkey signature does not match this decision"))?;
    sqlx::query(
        "UPDATE console_passkeys SET sign_count=$1, last_used_at=now() WHERE credential_id=$2",
    )
    .bind(i64::from(count))
    .bind(&credential_id)
    .execute(pool)
    .await
    .map_err(storage)?;
    let decision_id = random_id("cd_");
    let assertion = PasskeyAssertion {
        credential_id,
        ..request.assertion
    };
    sqlx::query(
        "INSERT INTO console_decisions(decision_id,account_id,member_id,approval_id,approve,payload,assertion,passkey_name,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())",
    )
    .bind(&decision_id)
    .bind(&account_id)
    .bind(&payload.node)
    .bind(&payload.approval_id)
    .bind(payload.approve)
    .bind(&request.payload)
    .bind(serde_json::to_value(&assertion).map_err(|_| invalid("malformed assertion"))?)
    .bind(row.get::<String, _>("name"))
    .execute(pool)
    .await
    .map_err(storage)?;
    Ok(Json(json!({"decision_id": decision_id})))
}

#[derive(Deserialize)]
struct AuditQuery {
    member: Option<String>,
    /// The `next` value of the previous page.
    before: Option<String>,
    limit: Option<i64>,
}

/// Audit events uploaded by the account's nodes, newest first.
async fn list_audit(
    State(state): State<CloudApiState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let account_id = session(&state, &headers).await?;
    let limit = query.limit.unwrap_or(100).clamp(1, 200);
    // The cursor is `RFC3339|member|seq` of the last event shown.
    let cursor = match &query.before {
        None => None,
        Some(text) => {
            let mut parts = text.splitn(3, '|');
            let (Some(at), Some(member), Some(seq)) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(invalid("invalid cursor"));
            };
            let at = DateTime::parse_from_rfc3339(at)
                .map_err(|_| invalid("invalid cursor"))?
                .with_timezone(&Utc);
            let seq: i64 = seq.parse().map_err(|_| invalid("invalid cursor"))?;
            Some((at, member.to_owned(), seq))
        }
    };
    let (at, member, seq) = cursor.unwrap_or((Utc::now() + Duration::days(3650), String::new(), 0));
    let has_cursor = query.before.is_some();
    let rows = sqlx::query(
        "SELECT a.member_id, m.name, a.seq, a.event, a.occurred_at FROM console_node_audit a \
         JOIN relay_members m ON m.member_id=a.member_id \
         WHERE a.account_id=$1 AND ($2::TEXT IS NULL OR a.member_id=$2) \
         AND (NOT $3 OR (a.occurred_at, a.member_id, a.seq) < ($4, $5, $6)) \
         ORDER BY a.occurred_at DESC, a.member_id DESC, a.seq DESC LIMIT $7",
    )
    .bind(&account_id)
    .bind(query.member.as_deref())
    .bind(has_cursor)
    .bind(at)
    .bind(member)
    .bind(seq)
    .bind(limit)
    .fetch_all(state.repository.pool())
    .await
    .map_err(storage)?;
    let next = (rows.len() as i64 == limit)
        .then(|| rows.last())
        .flatten()
        .map(|row| {
            format!(
                "{}|{}|{}",
                row.get::<DateTime<Utc>, _>("occurred_at").to_rfc3339(),
                row.get::<String, _>("member_id"),
                row.get::<i64, _>("seq"),
            )
        });
    Ok(Json(json!({
        "events": rows.iter().map(|row| json!({
            "member_id": row.get::<String, _>("member_id"),
            "node": row.get::<String, _>("name"),
            "seq": row.get::<i64, _>("seq"),
            "event": row.get::<Value, _>("event"),
        })).collect::<Vec<_>>(),
        "next": next,
    })))
}
