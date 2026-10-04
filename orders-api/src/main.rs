//! Resource server that accepts PingFederate-minted Biscuits.
//!
//! Every request is authorized offline: the token is verified against the PingFederate root
//! public key, then a Datalog authorizer combines the token's facts and checks with ambient
//! facts about this request (time, audience, operation, resource, client certificate).

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use biscuit_auth::{
    builder::{fact, string, AuthorizerBuilder},
    datalog::RunLimits,
    Biscuit, PublicKey,
};
use serde_json::json;

const AUDIENCE: &str = "orders-api";

struct Config {
    root_key: PublicKey,
    attest_key: Option<String>,
    revocation_file: Option<String>,
}

#[tokio::main]
async fn main() {
    let root_key: PublicKey = std::env::var("BISCUIT_ROOT_PUBLIC_KEY")
        .expect("BISCUIT_ROOT_PUBLIC_KEY (ed25519/<hex>) is required")
        .parse()
        .expect("invalid BISCUIT_ROOT_PUBLIC_KEY");
    let config = Arc::new(Config {
        root_key,
        attest_key: std::env::var("BISCUIT_ATTEST_PUBLIC_KEY").ok(),
        revocation_file: std::env::var("BISCUIT_REVOCATION_FILE").ok(),
    });

    let app = Router::new()
        .route("/orders/{id}", get(handle).post(handle))
        .with_state(config);

    let addr: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8091".into())
        .parse()
        .expect("invalid LISTEN");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot listen on {addr}: {e}"));
    println!("orders-api listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn handle(
    State(config): State<Arc<Config>>,
    method: Method,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = if method == Method::GET { "read" } else { "write" };
    let resource = format!("/orders/{id}");

    match authorize(&config, &headers, operation, &resource) {
        Ok(user) => (
            StatusCode::OK,
            Json(json!({ "allowed": true, "user": user, "operation": operation, "resource": resource })),
        ),
        Err((status, reason)) => (
            status,
            Json(json!({ "allowed": false, "operation": operation, "resource": resource, "reason": reason })),
        ),
    }
}

fn authorize(
    config: &Config,
    headers: &HeaderMap,
    operation: &str,
    resource: &str,
) -> Result<String, (StatusCode, String)> {
    let unauthorized = |reason: String| (StatusCode::UNAUTHORIZED, reason);
    let forbidden = |reason: String| (StatusCode::FORBIDDEN, reason);

    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("missing bearer token".into()))?;

    let token = Biscuit::from_base64(raw.trim(), config.root_key)
        .map_err(|e| unauthorized(format!("invalid token: {e}")))?;

    // Revoking any block's ID revokes that block and everything appended after it.
    let revoked = revoked_ids(config);
    if token
        .revocation_identifiers()
        .iter()
        .any(|id| revoked.contains(&hex::encode(id)))
    {
        return Err(unauthorized("token revoked".into()));
    }

    // Ambient facts describe *this request*. The token can only add checks against them;
    // the minter refuses to put these fact names in the authority block.
    let mut builder = AuthorizerBuilder::new()
        .time()
        .fact(fact("audience", &[string(AUDIENCE)]))
        .and_then(|b| b.fact(fact("operation", &[string(operation)])))
        .and_then(|b| b.fact(fact("resource", &[string(resource)])))
        .map_err(|e| forbidden(e.to_string()))?;

    // Stand-in for mTLS: a TLS terminator would forward the verified client cert thumbprint.
    if let Some(thumb) = headers
        .get("x-client-cert-sha256")
        .and_then(|v| v.to_str().ok())
    {
        builder = builder
            .fact(fact("tls_client_cert_sha256", &[string(thumb)]))
            .map_err(|e| forbidden(e.to_string()))?;
    }

    // Writes need MFA, and only an amr fact signed by the PingFederate attestation key counts.
    // Without an attestation key configured, writes are never allowed.
    // `trusting` replaces the rule's default scope, so `authority` must be listed again or the
    // scope(...) facts PingFederate put in the authority block would no longer be visible.
    let mut policy = String::from(r#"allow if scope("orders:read"), operation("read");"#);
    if let Some(attest) = &config.attest_key {
        policy.push_str(&format!(
            r#"
            allow if scope("orders:write"), operation("write"), amr("mfa") trusting authority, {attest};"#
        ));
    }
    policy.push_str("\ndeny if true;");

    let mut authorizer = builder
        .code(&policy)
        .map_err(|e| forbidden(format!("policy error: {e}")))?
        .set_limits(RunLimits {
            max_time: Duration::from_millis(20),
            ..Default::default()
        })
        .build(&token)
        .map_err(|e| forbidden(e.to_string()))?;

    if let Err(e) = authorizer.authorize() {
        return Err(forbidden(explain_denial(
            config,
            &token,
            &mut authorizer,
            operation,
            e.to_string(),
        )));
    }

    let users: Vec<(String,)> = authorizer
        .query(r#"u($u) <- user($u)"#)
        .map_err(|e| forbidden(e.to_string()))?;
    Ok(users.into_iter().next().map(|(u,)| u).unwrap_or_default())
}

/// A failed token check already names itself. But when no allow policy matched, Biscuit just
/// reports the catch-all `deny`, so spell out which requirement this request is missing.
fn explain_denial(
    config: &Config,
    token: &Biscuit,
    authorizer: &mut biscuit_auth::Authorizer,
    operation: &str,
    error: String,
) -> String {
    if !error.ends_with("the following checks failed: ") {
        return error;
    }
    let has_scope = |authorizer: &mut biscuit_auth::Authorizer, scope: &str| {
        authorizer
            .query::<_, (String,), _>(r#"s($s) <- scope($s)"#)
            .map(|rows| rows.iter().any(|(s,)| s == scope))
            .unwrap_or(false)
    };

    if operation == "read" {
        return r#"read requires scope("orders:read")"#.into();
    }
    let Some(attest) = &config.attest_key else {
        return "writes are disabled: orders-api has no PingFederate attestation key \
                (BISCUIT_ATTEST_PUBLIC_KEY)"
            .into();
    };
    let mut missing = Vec::new();
    if !has_scope(authorizer, "orders:write") {
        missing.push(r#"scope("orders:write")"#.to_string());
    }
    let attested = token
        .external_public_keys()
        .iter()
        .flatten()
        .any(|k| k.to_string().eq_ignore_ascii_case(attest));
    if !attested {
        missing.push(format!(r#"amr("mfa") signed by {attest} (step-up)"#));
    }
    if missing.is_empty() {
        error
    } else {
        format!("write requires {}", missing.join(" and "))
    }
}

fn revoked_ids(config: &Config) -> HashSet<String> {
    config
        .revocation_file
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
