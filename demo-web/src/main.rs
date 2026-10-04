//! Browser front end for the PingFederate x Biscuit demo.
//!
//! Log in through PingFederate (HTML form, authorization code), exchange the access token for a
//! Biscuit (RFC 8693), then call orders-api, step up with an MFA attestation, attenuate and seal,
//! and watch the Datalog change. Biscuit work happens in-process with biscuit-auth.

mod page;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use biscuit_auth::{
    builder::{date, string, Algorithm, BlockBuilder},
    PrivateKey, PublicKey, UnverifiedBiscuit,
};
use serde::Deserialize;

pub struct Config {
    pf_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,
    token_type: String,
    orders_api: String,
    root_key: Option<PublicKey>,
    attest_key: Option<PrivateKey>,
}

#[derive(Default)]
pub struct Session {
    state: Option<String>,
    jwt: Option<String>,
    biscuit: Option<String>,
    sealed: bool,
    exchange_trace: Option<HttpTrace>,
    events: Vec<Event>,
}

pub struct Event {
    pub label: String,
    pub ok: bool,
    pub status: String,
    pub detail: String,
    /// The HTTP call behind this event, when there was one.
    pub trace: Option<HttpTrace>,
}

struct App {
    config: Config,
    http: reqwest::Client,
    sessions: Mutex<HashMap<String, Session>>,
}

type Shared = Arc<App>;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() {
    let config = Config {
        pf_url: env_or("PF_RUNTIME_URL", "https://localhost:9031"),
        client_id: env_or("CLIENT_ID", "orders-web"),
        client_secret: std::env::var("CLIENT_SECRET").expect("CLIENT_SECRET is required"),
        redirect_uri: env_or("REDIRECT_URI", "http://localhost:8090/callback"),
        scopes: env_or("SCOPES", "orders:read orders:write"),
        token_type: env_or("BISCUIT_TOKEN_TYPE", "urn:darkedges:params:oauth:token-type:biscuit"),
        orders_api: env_or("ORDERS_API", "http://127.0.0.1:8091"),
        root_key: std::env::var("BISCUIT_ROOT_PUBLIC_KEY")
            .ok()
            .map(|k| k.parse().expect("invalid BISCUIT_ROOT_PUBLIC_KEY")),
        attest_key: std::env::var("ATTEST_PRIVATE_KEY").ok().map(|k| {
            PrivateKey::from_bytes_hex(k.trim(), Algorithm::Ed25519)
                .expect("invalid ATTEST_PRIVATE_KEY")
        }),
    };

    // PingFederate's runtime uses a self-signed certificate in this local setup.
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let app = Arc::new(App {
        config,
        http,
        sessions: Mutex::new(HashMap::new()),
    });

    let router = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/action", post(action))
        .route("/logout", get(logout))
        .with_state(app);

    let addr: SocketAddr = env_or("LISTEN", "127.0.0.1:8090").parse().expect("invalid LISTEN");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot listen on {addr}: {e}"));
    println!("demo-web listening on http://localhost:{}", addr.port());
    axum::serve(listener, router).await.unwrap();
}

// ---- sessions -------------------------------------------------------------------------------

const COOKIE: &str = "demo_sid";

fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().strip_prefix(&format!("{COOKIE}=")))
        .map(str::to_string)
        .next()
}

/// Returns the caller's session id, creating a session (and cookie) when there is none.
fn ensure_session(app: &App, headers: &HeaderMap) -> (String, Option<HeaderValue>) {
    let mut sessions = app.sessions.lock().unwrap();
    if let Some(id) = session_id(headers).filter(|id| sessions.contains_key(id)) {
        return (id, None);
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    sessions.insert(id.clone(), Session::default());
    let cookie = format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax");
    (id, Some(HeaderValue::from_str(&cookie).unwrap()))
}

fn with_cookie(mut response: Response, cookie: Option<HeaderValue>) -> Response {
    if let Some(c) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, c);
    }
    response
}

fn record(app: &App, sid: &str, event: Event) {
    if let Some(s) = app.sessions.lock().unwrap().get_mut(sid) {
        // Oldest first; keep the most recent 25.
        s.events.push(event);
        let excess = s.events.len().saturating_sub(25);
        s.events.drain(..excess);
    }
}

// ---- pages ----------------------------------------------------------------------------------

#[derive(Deserialize)]
struct IndexParams {
    tab: Option<String>,
}

async fn index(State(app): State<Shared>, headers: HeaderMap, Query(params): Query<IndexParams>) -> Response {
    let tab = match params.tab.as_deref() {
        Some("activity") => "activity",
        _ => "token",
    };
    let (sid, cookie) = ensure_session(&app, &headers);
    let html = {
        let sessions = app.sessions.lock().unwrap();
        let session = &sessions[&sid];
        let view = page::View {
            logged_in: session.jwt.is_some(),
            claims: session.jwt.as_deref().and_then(jwt_claims),
            biscuit: session.biscuit.as_deref().map(|b| describe(&app.config, b, session.sealed)),
            events: &session.events,
            exchange: session.exchange_trace.as_ref(),
            tab,
            attest_enabled: app.config.attest_key.is_some(),
            pf_url: &app.config.pf_url,
            orders_api: &app.config.orders_api,
        };
        page::render(&view)
    };
    with_cookie(Html(html).into_response(), cookie)
}

async fn login(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let (sid, cookie) = ensure_session(&app, &headers);
    let state = uuid::Uuid::new_v4().simple().to_string();
    app.sessions.lock().unwrap().get_mut(&sid).unwrap().state = Some(state.clone());

    let c = &app.config;
    let mut url = reqwest::Url::parse(&format!("{}/as/authorization.oauth2", c.pf_url)).unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &c.client_id)
        .append_pair("redirect_uri", &c.redirect_uri)
        .append_pair("scope", &c.scopes)
        .append_pair("state", &state);
    with_cookie(Redirect::to(url.as_str()).into_response(), cookie)
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(app): State<Shared>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let (sid, cookie) = ensure_session(&app, &headers);
    let expected = app.sessions.lock().unwrap().get_mut(&sid).unwrap().state.take();

    let result = async {
        if let Some(err) = params.error {
            return Err(format!("{err}: {}", params.error_description.unwrap_or_default()));
        }
        if expected.is_none() || params.state != expected {
            return Err("state mismatch; start the login again".to_string());
        }
        let code = params.code.ok_or("no authorization code")?;
        let c = &app.config;
        let (status, tokens, trace) = post_token(
            &app,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &c.redirect_uri),
            ],
        )
        .await?;
        let label = "Authorization code → access token (JWT)";
        if !status.is_success() {
            let error = token_error(status, &tokens);
            record(&app, &sid, traced(fail(label, &status.as_u16().to_string(), error.clone()), trace));
            return Err(error);
        }
        let jwt = field(&tokens, "access_token")?;
        let detail = format!("token_type={} expires_in={}", tokens["token_type"].as_str().unwrap_or("?"), tokens["expires_in"]);
        record(&app, &sid, traced(ok(label, &status.as_u16().to_string(), detail), trace));
        let biscuit = exchange(&app, &sid, &jwt).await?;
        Ok((jwt, biscuit))
    }
    .await;

    match result {
        Ok((jwt, (biscuit, _))) => {
            let mut sessions = app.sessions.lock().unwrap();
            let s = sessions.get_mut(&sid).unwrap();
            s.jwt = Some(jwt);
            s.biscuit = Some(biscuit);
            s.sealed = false;
        }
        Err(e) => record(&app, &sid, fail("Login failed", "error", e)),
    }
    with_cookie(Redirect::to("/").into_response(), cookie)
}

async fn logout(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(sid) = session_id(&headers) {
        app.sessions.lock().unwrap().remove(&sid);
    }
    Redirect::to("/").into_response()
}

// ---- actions --------------------------------------------------------------------------------

#[derive(Deserialize)]
struct ActionForm {
    op: String,
    #[serde(default)]
    order_id: String,
    #[serde(default)]
    datalog: String,
}

async fn action(State(app): State<Shared>, headers: HeaderMap, Form(form): Form<ActionForm>) -> Response {
    let (sid, cookie) = ensure_session(&app, &headers);
    let (jwt, biscuit, sealed) = {
        let sessions = app.sessions.lock().unwrap();
        let s = &sessions[&sid];
        (s.jwt.clone(), s.biscuit.clone(), s.sealed)
    };
    let (Some(jwt), Some(biscuit)) = (jwt, biscuit) else {
        return with_cookie(Redirect::to("/").into_response(), cookie);
    };

    let order_id = form.order_id.trim();
    let order_ok = !order_id.is_empty()
        && order_id.len() <= 32
        && order_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let resource = format!("/orders/{order_id}");

    // Operations that produce a new Biscuit return it; calls to orders-api just record an event.
    let outcome: Result<Option<(String, bool, String)>, String> = match form.op.as_str() {
        "mfa" | "readonly" | "order" | "ttl" | "custom" | "seal" if sealed => {
            Err("the Biscuit is sealed, so no block can be appended; get a fresh one".into())
        }
        "read" | "write" if !order_ok => Err("order id must be 1-32 letters, digits, - or _".into()),
        "read" | "write" => {
            let event = call_orders(&app, &biscuit, &form.op, &resource).await;
            record(&app, &sid, event);
            Ok(None)
        }
        "mfa" => step_up(&app.config, &biscuit)
            .map(|b| Some((b, false, r#"amr("mfa") third-party block appended"#.into()))),
        "readonly" => attenuate(&biscuit, BlockBuilder::new().code(r#"check if operation("read");"#))
            .map(|b| Some((b, false, r#"check if operation("read")"#.into()))),
        "order" if !order_ok => Err("order id must be 1-32 letters, digits, - or _".into()),
        "order" => {
            let params = HashMap::from([("res".to_string(), string(&resource))]);
            attenuate(
                &biscuit,
                BlockBuilder::new().code_with_params(r#"check if resource($r), $r == {res};"#, params, HashMap::new()),
            )
            .map(|b| Some((b, false, format!(r#"check if resource($r), $r == "{resource}""#))))
        }
        "ttl" => {
            let exp = SystemTime::now() + Duration::from_secs(60);
            let params = HashMap::from([("exp".to_string(), date(&exp))]);
            attenuate(
                &biscuit,
                BlockBuilder::new().code_with_params("check if time($t), $t <= {exp};", params, HashMap::new()),
            )
            .map(|b| Some((b, false, "expires in 60 seconds".into())))
        }
        "custom" => attenuate(&biscuit, BlockBuilder::new().code(form.datalog.trim()))
            .map(|b| Some((b, false, form.datalog.trim().to_string()))),
        "seal" => UnverifiedBiscuit::from_base64(&biscuit)
            .and_then(|t| t.seal())
            .and_then(|t| t.to_base64())
            .map(|b| Some((b, true, "no more blocks can be appended".into())))
            .map_err(|e| e.to_string()),
        "reset" => exchange(&app, &sid, &jwt).await.map(|(b, detail)| Some((b, false, detail))),
        other => Err(format!("unknown action {other}")),
    };

    let label = match form.op.as_str() {
        "mfa" => "Step-up: MFA attestation",
        "readonly" => "Attenuate: read-only",
        "order" => "Attenuate: one order",
        "ttl" => "Attenuate: 60 s lifetime",
        "custom" => "Attenuate: custom block",
        "seal" => "Seal",
        "reset" => "Fresh Biscuit from PingFederate",
        "read" => "GET order",
        "write" => "POST order",
        _ => "Action",
    };
    match outcome {
        Ok(Some((new_biscuit, sealed, detail))) => {
            {
                let mut sessions = app.sessions.lock().unwrap();
                let s = sessions.get_mut(&sid).unwrap();
                s.biscuit = Some(new_biscuit);
                // Sealing is permanent for that token; a fresh exchange starts unsealed.
                s.sealed = sealed || (s.sealed && form.op != "reset");
            }
            // The exchange already logged itself, with its HTTP trace.
            if form.op != "reset" {
                record(&app, &sid, ok(label, "ok", detail));
            }
        }
        Ok(None) => {}
        Err(e) => record(&app, &sid, fail(label, "refused", e)),
    }
    // HTTP calls land on their request/response; token changes land on the Datalog.
    let to = match form.op.as_str() {
        "read" | "write" | "reset" => "/?tab=activity#latest",
        _ => "/?tab=token",
    };
    with_cookie(Redirect::to(to).into_response(), cookie)
}

fn attenuate(biscuit: &str, block: Result<BlockBuilder, biscuit_auth::error::Token>) -> Result<String, String> {
    let block = block.map_err(|e| format!("invalid Datalog: {e}"))?;
    UnverifiedBiscuit::from_base64(biscuit)
        .and_then(|t| t.append(block))
        .and_then(|t| t.to_base64())
        .map_err(|e| e.to_string())
}

/// Stand-in for PingFederate signing a third-party block after step-up MFA. biscuit-java 4.0.1
/// can't read the v3.3 third-party request format yet, so the plugin can't do this itself.
fn step_up(config: &Config, biscuit: &str) -> Result<String, String> {
    let key = config
        .attest_key
        .as_ref()
        .ok_or("no attestation key configured (ATTEST_PRIVATE_KEY)")?;
    let token = UnverifiedBiscuit::from_base64(biscuit).map_err(|e| e.to_string())?;
    let block = token
        .third_party_request()
        .and_then(|req| req.create_block(key, BlockBuilder::new().code(r#"amr("mfa");"#)?))
        .and_then(|b| b.serialize())
        .map_err(|e| e.to_string())?;
    token
        .append_third_party(&block)
        .and_then(|t| t.to_base64())
        .map_err(|e| e.to_string())
}

async fn call_orders(app: &App, biscuit: &str, op: &str, resource: &str) -> Event {
    let url = format!("{}{resource}", app.config.orders_api);
    let method = if op == "read" { "GET" } else { "POST" };
    let request = if op == "read" { app.http.get(&url) } else { app.http.post(&url) };
    let label = format!("{method} {resource}");
    let started = std::time::Instant::now();
    match request.bearer_auth(biscuit).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let detail = match (json["allowed"].as_bool(), json["user"].as_str(), json["reason"].as_str()) {
                (Some(true), Some(user), _) => format!("allowed for {user}"),
                (_, _, Some(reason)) => reason.to_string(),
                _ => body.clone(),
            };
            // The Biscuit goes in verbatim: it's this session's own token, and the command runs as-is.
            let trace = HttpTrace {
                curl: format!(
                    "curl -X {method} {} \\\n  -H {}",
                    shell_quote(&url),
                    shell_quote(&format!("Authorization: Bearer {biscuit}"))
                ),
                status: status_line(status),
                elapsed_ms: started.elapsed().as_millis(),
                response: serde_json::to_string_pretty(&json).unwrap_or(body),
            };
            let event = if status.is_success() { ok(&label, "", detail) } else { fail(&label, "", detail) };
            traced(Event { status: status.as_u16().to_string(), ..event }, trace)
        }
        Err(e) => fail(&label, "unreachable", format!("orders-api at {}: {e}", app.config.orders_api)),
    }
}

// ---- PingFederate ---------------------------------------------------------------------------

/// One HTTP call this app made, as an equivalent curl command plus what came back.
#[derive(Clone)]
pub struct HttpTrace {
    pub curl: String,
    pub status: String,
    pub elapsed_ms: u128,
    pub response: String,
}

async fn post_token(
    app: &App,
    params: &[(&str, &str)],
) -> Result<(reqwest::StatusCode, serde_json::Value, HttpTrace), String> {
    let c = &app.config;
    let url = format!("{}/as/token.oauth2", c.pf_url);
    let started = std::time::Instant::now();
    let resp = app
        .http
        .post(&url)
        .basic_auth(&c.client_id, Some(&c.client_secret))
        .form(params)
        .send()
        .await
        .map_err(|e| format!("PingFederate unreachable: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let trace = HttpTrace {
        curl: curl_command(&url, &c.client_id, params),
        status: status_line(status),
        elapsed_ms: started.elapsed().as_millis(),
        response: serde_json::to_string_pretty(&json).unwrap_or(body),
    };
    Ok((status, json, trace))
}

fn status_line(status: reqwest::StatusCode) -> String {
    format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The client secret is left as $CLIENT_SECRET so the command can be shared and re-run
/// (`make tf-creds` prints it).
fn curl_command(url: &str, client_id: &str, params: &[(&str, &str)]) -> String {
    let mut cmd = format!("curl -k -X POST {} \\\n  -u \"{client_id}:$CLIENT_SECRET\"", shell_quote(url));
    for (name, value) in params {
        cmd.push_str(&format!(" \\\n  --data-urlencode {}", shell_quote(&format!("{name}={value}"))));
    }
    cmd
}

fn token_error(status: reqwest::StatusCode, json: &serde_json::Value) -> String {
    format!(
        "{status}: {} {}",
        json["error"].as_str().unwrap_or("error"),
        json["error_description"].as_str().unwrap_or("")
    )
}

/// RFC 8693 exchange of the PingFederate access token for a Biscuit. The request and response
/// are logged and kept on the session so the page can show them, including failed attempts.
async fn exchange(app: &App, sid: &str, jwt: &str) -> Result<(String, String), String> {
    let (status, json, trace) = post_token(
        app,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", jwt),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("requested_token_type", &app.config.token_type),
        ],
    )
    .await?;
    if let Some(s) = app.sessions.lock().unwrap().get_mut(sid) {
        s.exchange_trace = Some(trace.clone());
    }
    let label = "Token exchange: JWT → Biscuit";
    let code = status.as_u16().to_string();
    if !status.is_success() {
        let error = token_error(status, &json);
        record(app, sid, traced(fail(label, &code, error.clone()), trace));
        return Err(error);
    }
    let biscuit = field(&json, "access_token")?;
    let detail = format!(
        "issued_token_type={} expires_in={}",
        json["issued_token_type"].as_str().unwrap_or("?"),
        json["expires_in"]
    );
    record(app, sid, traced(ok(label, &code, detail.clone()), trace));
    Ok((biscuit, detail))
}

fn field(json: &serde_json::Value, name: &str) -> Result<String, String> {
    json[name]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("response has no {name}: {json}"))
}

fn ok(label: &str, status: &str, detail: String) -> Event {
    Event { label: label.into(), ok: true, status: status.into(), detail, trace: None }
}

fn fail(label: &str, status: &str, detail: String) -> Event {
    Event { label: label.into(), ok: false, status: status.into(), detail, trace: None }
}

fn traced(event: Event, trace: HttpTrace) -> Event {
    Event { trace: Some(trace), ..event }
}

// ---- token views ----------------------------------------------------------------------------

fn jwt_claims(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    serde_json::to_string_pretty(&json).ok()
}

pub struct BlockView {
    pub kind: &'static str,
    pub signer: Option<String>,
    pub revocation_id: String,
    pub source: String,
}

pub struct BiscuitView {
    pub token: String,
    pub size: usize,
    pub sealed: bool,
    pub verified: Option<Result<(), String>>,
    pub blocks: Vec<BlockView>,
}

fn describe(config: &Config, token: &str, sealed: bool) -> BiscuitView {
    let parsed = UnverifiedBiscuit::from_base64(token);
    let blocks = match &parsed {
        Ok(t) => {
            let keys = t.external_public_keys();
            let ids = t.revocation_identifiers();
            (0..t.block_count())
                .map(|i| {
                    let signer = keys.get(i).cloned().flatten().map(|k| k.to_string());
                    BlockView {
                        kind: match (i, &signer) {
                            (0, _) => "authority · minted by PingFederate",
                            (_, Some(_)) => "third-party · attestation",
                            _ => "attenuation",
                        },
                        signer,
                        revocation_id: ids.get(i).map(hex::encode).unwrap_or_default(),
                        source: t.print_block_source(i).unwrap_or_else(|e| e.to_string()),
                    }
                })
                .collect()
        }
        Err(e) => vec![BlockView {
            kind: "unreadable",
            signer: None,
            revocation_id: String::new(),
            source: e.to_string(),
        }],
    };
    let verified = config.root_key.map(|key| {
        UnverifiedBiscuit::from_base64(token)
            .map_err(|e| e.to_string())
            .and_then(|t| t.verify(key).map(|_| ()).map_err(|e| e.to_string()))
    });
    BiscuitView {
        token: token.to_string(),
        size: URL_SAFE_NO_PAD.decode(token.trim_end_matches('=')).map(|b| b.len()).unwrap_or(0),
        sealed,
        verified,
        blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::curl_command;

    #[test]
    fn curl_command_quotes_values_and_hides_the_secret() {
        let cmd = curl_command(
            "https://localhost:9031/as/token.oauth2",
            "orders-web",
            &[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("x", "it's")],
        );
        assert_eq!(
            cmd,
            [
                r#"curl -k -X POST 'https://localhost:9031/as/token.oauth2' \"#,
                r#"  -u "orders-web:$CLIENT_SECRET" \"#,
                r#"  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \"#,
                r#"  --data-urlencode 'x=it'\''s'"#,
            ]
            .join("\n")
        );
    }

    /// Prints the exact command the page shows, for a given JWT (used to try it by hand).
    #[test]
    #[ignore]
    fn print_exchange_curl() {
        let jwt = std::env::var("JWT").unwrap();
        println!(
            "{}",
            curl_command(
                "https://localhost:9031/as/token.oauth2",
                "orders-web",
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                    ("subject_token", &jwt),
                    ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
                    ("requested_token_type", "urn:darkedges:params:oauth:token-type:biscuit"),
                ],
            )
        );
    }
}
