//! Built-in policy rules for the desktop and mobile owner clients.

use super::*;

pub(crate) fn desktop_owner_rule(agent_id: AgentId, vault_id: &VaultId) -> PolicyRule {
    PolicyRule {
        id: "builtin_desktop_owner".into(),
        version: 1,
        effect: PolicyEffect::Allow,
        agent_id: Some(agent_id),
        connection_id: None,
        resource_prefix: format!("kl://{}", vault_id.0),
        actions: [
            "entry:search",
            "entry:read_metadata",
            "entry:read_fields",
            "entry:read_username",
            "entry:read_secret",
            "entry:create",
            "entry:update_standard_fields",
            "entry:update_protected_fields",
            "entry:update_totp",
            "entry:move",
            "entry:delete",
            "group:create",
            "group:update",
            "group:delete",
            "connection:list",
            "connection:add",
            "connection:enroll",
            "connection:unenroll",
            "connection:test",
            "connection:refresh",
            "connection:disconnect",
            "connection:revoke",
            "approval:list",
            "approval:decide",
            "trust:list",
            "trust:revoke",
            "client:enroll",
            "audit:query",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        argument_equals: Default::default(),
        not_before: None,
        expires_at: None,
        max_lease_ttl_seconds: 600,
        max_uses: 100,
        budget: DataBudget {
            max_items: Some(100),
            max_cells: Some(10_000),
            max_response_bytes: Some(1_048_576),
            max_rows_changed: Some(1_000),
            max_concurrent: Some(1),
            ..Default::default()
        },
    }
}

/// The authority a phone gets over its own vault.
///
/// Deliberately narrower than [`desktop_owner_rule`]. A phone is more easily
/// lost and less easily inspected than a desktop, so it may use and defend the
/// vault but not widen it. Compared with the desktop rule this drops:
///
/// - `connection:add` and `connection:enroll` — a stolen unlocked phone must not
///   be able to mint new connector credentials.
/// - the lease and gate actions — connector execution belongs on the machine
///   that hosts the Gateway.
///
/// It keeps `connection:disconnect` and `connection:revoke`, because the phone
/// is often the device you have to hand when you need to cut something off.
pub(crate) fn mobile_owner_rule(agent_id: AgentId, vault_id: &VaultId) -> PolicyRule {
    PolicyRule {
        id: "builtin_mobile_owner".into(),
        version: 1,
        effect: PolicyEffect::Allow,
        agent_id: Some(agent_id),
        connection_id: None,
        resource_prefix: format!("kl://{}", vault_id.0),
        actions: [
            "entry:search",
            "entry:read_metadata",
            "entry:read_fields",
            "entry:read_username",
            "entry:read_secret",
            "entry:create",
            "entry:update_standard_fields",
            "entry:update_protected_fields",
            "entry:update_totp",
            "entry:move",
            "entry:delete",
            "group:create",
            "group:update",
            "group:delete",
            "connection:list",
            "connection:test",
            "connection:refresh",
            "connection:disconnect",
            "connection:revoke",
            "approval:list",
            "approval:decide",
            "trust:list",
            "trust:revoke",
            "audit:query",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        argument_equals: Default::default(),
        not_before: None,
        expires_at: None,
        max_lease_ttl_seconds: 600,
        max_uses: 100,
        budget: DataBudget {
            max_items: Some(100),
            max_cells: Some(10_000),
            max_response_bytes: Some(1_048_576),
            max_rows_changed: Some(1_000),
            max_concurrent: Some(1),
            ..Default::default()
        },
    }
}

pub(crate) async fn capture_google_oauth_callback(
    listener: TcpListener,
    flows: Arc<Mutex<HashMap<String, GoogleOAuthFlow>>>,
    flow_id: String,
) {
    let capture = async {
        for _ in 0..16 {
            let (mut stream, peer) = listener.accept().await.map_err(|_| "listener failure")?;
            if !peer.ip().is_loopback() {
                let _ = write_oauth_http_response(&mut stream, 403, false).await;
                continue;
            }
            let target = match read_oauth_http_target(&mut stream).await {
                Ok(target) => target,
                Err(()) => {
                    let _ = write_oauth_http_response(&mut stream, 400, false).await;
                    continue;
                }
            };
            let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
                let _ = write_oauth_http_response(&mut stream, 400, false).await;
                continue;
            };
            if url.path() != "/oauth2/callback" {
                let _ = write_oauth_http_response(&mut stream, 404, false).await;
                continue;
            }
            let mut parameters = HashMap::new();
            let mut duplicate_parameter = false;
            for (key, value) in url.query_pairs().into_owned() {
                if parameters.insert(key, value).is_some() {
                    duplicate_parameter = true;
                    break;
                }
            }
            if duplicate_parameter {
                let _ = write_oauth_http_response(&mut stream, 400, false).await;
                continue;
            }
            let state_valid = flows
                .lock()
                .ok()
                .and_then(|flows| flows.get(&flow_id).map(|flow| flow.state.clone()))
                .is_some_and(|state| parameters.get("state") == Some(&state));
            if !state_valid {
                let _ = write_oauth_http_response(&mut stream, 403, false).await;
                continue;
            }
            let callback = if let Some(error) = parameters.get("error") {
                GoogleOAuthCallback::Failed(safe_oauth_error(error))
            } else {
                let Some(code) = parameters.get("code").filter(|code| code.len() <= 4096) else {
                    let _ = write_oauth_http_response(&mut stream, 400, false).await;
                    continue;
                };
                let picked_file_ids = parameters
                    .get("picked_file_ids")
                    .map(|ids| {
                        ids.split(',')
                            .filter(|id| valid_google_file_id(id))
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                GoogleOAuthCallback::Received {
                    code: code.clone(),
                    picked_file_ids,
                    scope: parameters.get("scope").cloned().unwrap_or_default(),
                }
            };
            let success = matches!(callback, GoogleOAuthCallback::Received { .. });
            if let Ok(mut flows) = flows.lock()
                && let Some(flow) = flows.get_mut(&flow_id)
            {
                flow.callback = callback;
            }
            let _ = write_oauth_http_response(&mut stream, 200, success).await;
            return Ok::<(), &'static str>(());
        }
        Err("too many invalid callback attempts")
    };
    let failure = match tokio::time::timeout(GOOGLE_OAUTH_FLOW_TTL, capture).await {
        Ok(Ok(())) => None,
        Ok(Err(reason)) => Some(reason),
        Err(_) => Some("callback timed out"),
    };
    if failure.is_some()
        && let Ok(mut flows) = flows.lock()
    {
        flows.remove(&flow_id);
    }
}

pub(crate) async fn read_oauth_http_target(
    stream: &mut tokio::net::TcpStream,
) -> std::result::Result<String, ()> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while request.len() <= MAX_OAUTH_HTTP_BYTES {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    if request.len() > MAX_OAUTH_HTTP_BYTES {
        return Err(());
    }
    let request = std::str::from_utf8(&request).map_err(|_| ())?;
    let mut parts = request.lines().next().ok_or(())?.split_whitespace();
    if parts.next() != Some("GET") {
        return Err(());
    }
    let target = parts.next().ok_or(())?;
    if !target.starts_with('/') || target.len() > 12 * 1024 {
        return Err(());
    }
    Ok(target.into())
}

pub(crate) async fn write_oauth_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    success: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let body = if success {
        "<!doctype html><meta charset=utf-8><title>KeyLease</title><h1>Selection received</h1><p>Return to KeyLease to finish the connection.</p>"
    } else {
        "<!doctype html><meta charset=utf-8><title>KeyLease</title><h1>Request not accepted</h1><p>Return to KeyLease and retry the connection flow.</p>"
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}
