//! Server-rendered HTML for the demo. Everything dynamic goes through `esc`.

use crate::{BiscuitView, Event, HttpTrace};

pub struct View<'a> {
    pub logged_in: bool,
    pub claims: Option<String>,
    pub biscuit: Option<BiscuitView>,
    pub events: &'a [Event],
    pub exchange: Option<&'a HttpTrace>,
    /// Selected tab on the dashboard: "token" or "activity".
    pub tab: &'a str,
    pub attest_enabled: bool,
    pub pf_url: &'a str,
    pub orders_api: &'a str,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render(v: &View) -> String {
    let user = v
        .claims
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|j| j["username"].as_str().map(str::to_string));

    let header_right = match &user {
        Some(u) => format!(
            r#"<span class="who"><span class="dot"></span>{}</span><a class="link" href="/logout">Log out</a>"#,
            esc(u)
        ),
        None => String::new(),
    };

    let body = if v.logged_in { dashboard(v) } else { welcome(v) };

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Biscuit Playground</title>
<style>{CSS}</style>
</head>
<body>
<header class="top">
  <div class="brand"><span class="mark">◆</span> Biscuit <span class="x">×</span> PingFederate</div>
  <div class="right">{header_right}</div>
</header>
{body}
<script>
document.querySelectorAll("[data-copy]").forEach(function (b) {{
  b.addEventListener("click", function () {{
    var text = document.getElementById(b.dataset.copy).textContent;
    navigator.clipboard.writeText(text).then(function () {{
      var was = b.textContent; b.textContent = "Copied"; setTimeout(function () {{ b.textContent = was; }}, 1200);
    }});
  }});
}});
// Request / Response tabs: each [data-tabs] group switches independently.
document.querySelectorAll("[data-tabs]").forEach(function (group) {{
  var tabs = group.querySelectorAll(".io-tab");
  tabs.forEach(function (tab) {{
    tab.addEventListener("click", function () {{
      tabs.forEach(function (t) {{
        var on = t === tab;
        t.classList.toggle("active", on);
        t.setAttribute("aria-selected", on ? "true" : "false");
        document.getElementById(t.dataset.pane).hidden = !on;
      }});
    }});
  }});
}});
</script>
</body>
</html>"##
    )
}

fn welcome(v: &View) -> String {
    format!(
        r#"<main class="hero">
  <section class="card intro">
    <p class="eyebrow">Capability tokens, minted by your IdP</p>
    <h1>Log in, get a Biscuit, then narrow it yourself</h1>
    <ol class="steps">
      <li><b>Log in</b> with the PingFederate HTML form (alice or bob; passwords from <code>make tf-creds</code>).</li>
      <li><b>Token exchange</b>: the app swaps PingFederate's JWT for a Biscuit (RFC 8693).</li>
      <li><b>Call orders-api</b>: it checks the Biscuit offline with Datalog, with no call back to PingFederate.</li>
      <li><b>Step up and attenuate</b>: add an MFA attestation, restrict the token, seal it, and watch the blocks change.</li>
    </ol>
    <a class="btn primary big" href="/login">Log in with PingFederate</a>
    <p class="note">PingFederate runs at <code>{pf}</code> with a self-signed certificate. If the login page won't load, open that address once and accept the certificate.</p>
  </section>
  {events}
</main>"#,
        pf = esc(v.pf_url),
        events = if v.events.is_empty() {
            String::new()
        } else {
            format!(r#"<section class="card"><h2>Activity</h2>{}</section>"#, activity_log(v.events))
        },
    )
}

/// Request / Response tabs for one HTTP call: the request as a runnable curl command, the
/// response as status + JSON body, each with its own copy button. `id` must be unique on the page.
fn http_block(t: &HttpTrace, id: &str, note: &str) -> String {
    let ok = t.status.starts_with('2');
    format!(
        r#"<div class="http" data-tabs>
    <div class="io-bar" role="tablist">
      <button type="button" class="io-tab active" role="tab" aria-selected="true" data-pane="{id}-req">Request</button>
      <button type="button" class="io-tab" role="tab" aria-selected="false" data-pane="{id}-resp">Response <span class="chip {cls}">{status}</span></button>
      <span class="chip ms">{ms} ms</span>
    </div>
    <div class="io-pane" id="{id}-req" role="tabpanel">
      <div class="pane-head">{note}<button type="button" class="btn small-btn" data-copy="{id}-req-text">Copy curl</button></div>
      <pre class="code wrap" id="{id}-req-text">{curl}</pre>
    </div>
    <div class="io-pane" id="{id}-resp" role="tabpanel" hidden>
      <div class="pane-head"><button type="button" class="btn small-btn" data-copy="{id}-resp-text">Copy response</button></div>
      <pre class="code wrap" id="{id}-resp-text">{response}</pre>
    </div>
  </div>"#,
        curl = esc(&t.curl),
        cls = if ok { "good" } else { "bad" },
        status = esc(&t.status),
        ms = t.elapsed_ms,
        response = esc(&t.response),
    )
}

const SECRET_NOTE: &str =
    r#"<p class="hint">Set <code>CLIENT_SECRET</code> first (<code>make tf-creds</code>).</p>"#;

fn exchange_card(t: &HttpTrace) -> String {
    format!(
        r#"<details class="card" open>
  <summary><h2>Token exchange (RFC 8693)</h2><span class="hint">the request this app sent to PingFederate, and the reply</span></summary>
  {http}
</details>"#,
        http = http_block(t, "exchange", SECRET_NOTE),
    )
}

fn dashboard(v: &View) -> String {
    let biscuit = v.biscuit.as_ref().map(biscuit_card).unwrap_or_default();
    let exchange = v.exchange.map(exchange_card).unwrap_or_default();
    let claims = v
        .claims
        .as_deref()
        .map(|c| {
            format!(
                r#"<details class="card"><summary><h2>Access token (JWT) from PingFederate</h2><span class="hint">the subject_token for the exchange</span></summary><pre class="code">{}</pre></details>"#,
                esc(c)
            )
        })
        .unwrap_or_default();
    let sealed = v.biscuit.as_ref().map(|b| b.sealed).unwrap_or(false);
    let dis = if sealed { " disabled" } else { "" };
    let mfa_dis = if sealed || !v.attest_enabled { " disabled" } else { "" };
    let mfa_note = if v.attest_enabled {
        r#"Writes need <code>amr("mfa")</code> in a block signed by PingFederate's attestation key."#
    } else {
        "No attestation key configured (ATTEST_PRIVATE_KEY), so writes can't be unlocked. Start with <code>make web</code>."
    };
    let sealed_note = if sealed {
        r#"<p class="note warn">This Biscuit is sealed. Nothing more can be appended; get a fresh one to continue.</p>"#
    } else {
        ""
    };

    let activity_tab = v.tab == "activity";
    let tab_body = if activity_tab {
        let calls = v.events.iter().filter(|e| e.trace.is_some()).count();
        format!(
            r#"<section class="card">
      <div class="card-head"><h2>HTTP activity</h2><span class="hint">oldest first · {calls} HTTP call{s}, each shown as a runnable curl and the JSON that came back</span></div>
      {log}
    </section>"#,
            s = if calls == 1 { "" } else { "s" },
            log = if v.events.is_empty() {
                r#"<p class="hint">Nothing yet. Use the actions on the right.</p>"#.to_string()
            } else {
                activity_log(v.events)
            },
        )
    } else {
        format!("{biscuit}\n{exchange}\n{claims}")
    };
    let tab_class = |active: bool| if active { "tab active" } else { "tab" };

    format!(
        r#"<main class="grid">
  <section class="main-col">
    <nav class="tabs">
      <a class="{token_cls}" href="/?tab=token">Token</a>
      <a class="{activity_cls}" href="/?tab=activity#latest">HTTP activity <span class="count">{n}</span></a>
    </nav>
    {tab_body}
  </section>
  <aside class="side-col">
    <form class="card actions" method="post" action="/action">
      <h2>Call orders-api</h2>
      <p class="hint">{api}</p>
      <label class="field"><span>Order</span><span class="prefix">/orders/</span><input name="order_id" value="123" maxlength="32" autocomplete="off"></label>
      <div class="row">
        <button class="btn" name="op" value="read">GET · read</button>
        <button class="btn" name="op" value="write">POST · write</button>
      </div>

      <h2>Step up</h2>
      <p class="hint">{mfa_note}</p>
      <button class="btn accent" name="op" value="mfa"{mfa_dis}>Add MFA attestation</button>

      <h2>Attenuate <span class="tag">offline</span></h2>
      <p class="hint">Appending a block can only narrow the token, never widen it.</p>
      {sealed_note}
      <div class="row wrap">
        <button class="btn" name="op" value="readonly"{dis}>Read-only</button>
        <button class="btn" name="op" value="order"{dis}>Only this order</button>
        <button class="btn" name="op" value="ttl"{dis}>Expire in 60 s</button>
      </div>
      <textarea name="datalog" rows="3" spellcheck="false" placeholder='check if operation("read");'{dis}></textarea>
      <div class="row">
        <button class="btn" name="op" value="custom"{dis}>Append block</button>
        <button class="btn danger" name="op" value="seal"{dis}>Seal</button>
      </div>

      <h2>Start over</h2>
      <button class="btn" name="op" value="reset">Fresh Biscuit from PingFederate</button>
    </form>
    {last}
  </aside>
</main>"#,
        api = esc(v.orders_api),
        token_cls = tab_class(!activity_tab),
        activity_cls = tab_class(activity_tab),
        n = v.events.len(),
        last = last_result(v.events),
    )
}

fn biscuit_card(b: &BiscuitView) -> String {
    let verified = match &b.verified {
        Some(Ok(())) => r#"<span class="chip good">signature verified</span>"#.to_string(),
        Some(Err(e)) => format!(r#"<span class="chip bad" title="{}">signature invalid</span>"#, esc(e)),
        None => String::new(),
    };
    let sealed = if b.sealed { r#"<span class="chip warn">sealed</span>"# } else { "" };
    let blocks: String = b
        .blocks
        .iter()
        .enumerate()
        .map(|(i, blk)| {
            let class = match i {
                0 => "authority",
                _ if blk.signer.is_some() => "third",
                _ => "attenuation",
            };
            let signer = blk
                .signer
                .as_deref()
                .map(|s| format!(r#"<span class="mono small" title="{0}">signed by {1}…</span>"#, esc(s), esc(&s[..s.len().min(24)])))
                .unwrap_or_default();
            format!(
                r#"<div class="block {class}">
  <div class="block-head"><span class="idx">{i}</span><span class="kind">{kind}</span>{signer}<span class="mono small rid" title="revocation id {rid}">rev {rid_short}</span></div>
  <pre class="code">{src}</pre>
</div>"#,
                kind = esc(blk.kind),
                rid = esc(&blk.revocation_id),
                rid_short = esc(&blk.revocation_id[..blk.revocation_id.len().min(12)]),
                src = esc(blk.source.trim()),
            )
        })
        .collect();
    format!(
        r#"<section class="card">
  <div class="card-head"><h2>Biscuit</h2><div class="chips"><span class="chip">{n} block{s}</span><span class="chip">{size} bytes</span>{verified}{sealed}</div></div>
  <div class="blocks">{blocks}</div>
  <details class="raw"><summary>Raw token</summary><textarea readonly rows="4" spellcheck="false">{token}</textarea></details>
</section>"#,
        n = b.blocks.len(),
        s = if b.blocks.len() == 1 { "" } else { "s" },
        size = b.size,
        token = esc(&b.token),
    )
}

/// One row per event. Rows backed by an HTTP call carry Request / Response tabs.
fn activity_log(events: &[Event]) -> String {
    let rows: String = events
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let io = match &e.trace {
                Some(t) => {
                    let note = if t.curl.contains("$CLIENT_SECRET") { SECRET_NOTE } else { "" };
                    http_block(t, &format!("event-{i}"), note)
                }
                None => r#"<p class="hint local">No HTTP call: done locally with biscuit-auth.</p>"#.to_string(),
            };
            format!(
                r#"<article class="call"{latest}>
    <div class="call-head"><span class="seq">#{seq}</span><span class="pill {cls}">{status}</span><span class="label">{label}</span></div>
    <div class="detail">{detail}</div>
    {io}
  </article>"#,
                seq = i + 1,
                latest = if i + 1 == events.len() { r#" id="latest""# } else { "" },
                cls = if e.ok { "good" } else { "bad" },
                status = esc(&e.status),
                label = esc(&e.label),
                detail = esc(&e.detail),
            )
        })
        .collect();
    format!(r#"<div class="calls">{rows}</div>"#)
}

/// The newest result, so actions give feedback while the Token tab is showing.
fn last_result(events: &[Event]) -> String {
    let Some(e) = events.last() else {
        return String::new();
    };
    let link = if e.trace.is_some() {
        r#"<a class="link small" href="/?tab=activity#latest">See request &amp; response →</a>"#
    } else {
        ""
    };
    format!(
        r#"<section class="card last"><h2>Last result</h2>
  <div class="call-head"><span class="pill {cls}">{status}</span><span class="label">{label}</span></div>
  <div class="detail">{detail}</div>{link}
</section>"#,
        cls = if e.ok { "good" } else { "bad" },
        status = esc(&e.status),
        label = esc(&e.label),
        detail = esc(&e.detail),
    )
}

const CSS: &str = r#"
:root {
  --bg: #f6f5f1; --surface: #ffffff; --surface-2: #f1efe9; --text: #1d1c1a; --muted: #6b6860;
  --border: #e3e0d8; --accent: #b4532a; --accent-text: #ffffff; --good: #2f7a4b; --good-bg: #e3f2e8;
  --bad: #b3261e; --bad-bg: #fbe5e3; --warn: #8a5a00; --warn-bg: #fdf0d5;
  --auth: #b4532a; --third: #6a4bbf; --atten: #2f6f9a;
  --mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161514; --surface: #1f1e1c; --surface-2: #2a2826; --text: #ece9e2; --muted: #a29e94;
    --border: #34312d; --accent: #e07a4a; --accent-text: #1a1310; --good: #6fcf97; --good-bg: #1f3427;
    --bad: #f28b82; --bad-bg: #3a2120; --warn: #f2c063; --warn-bg: #3a2f17;
    --auth: #e07a4a; --third: #a58cf0; --atten: #6fb3e0;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
code, .mono, pre, textarea { font-family: var(--mono); }
code { font-size: .88em; background: var(--surface-2); padding: .05em .35em; border-radius: 4px; }
.top { display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 14px 24px; border-bottom: 1px solid var(--border); background: var(--surface); }
.brand { font-weight: 650; letter-spacing: -.01em; }
.brand .mark { color: var(--accent); } .brand .x { color: var(--muted); font-weight: 400; }
.right { display: flex; align-items: center; gap: 14px; }
.who { display: inline-flex; align-items: center; gap: 7px; font-weight: 600; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--good); }
.link { color: var(--muted); text-decoration: none; } .link:hover { color: var(--text); }

.hero { max-width: 720px; margin: 48px auto; padding: 0 16px; display: grid; gap: 16px; }
.grid { max-width: 1240px; margin: 24px auto; padding: 0 16px; display: grid;
  grid-template-columns: minmax(0, 1fr) 360px; gap: 16px; align-items: start; }
.main-col, .side-col { display: grid; gap: 16px; min-width: 0; }
@media (max-width: 900px) { .grid { grid-template-columns: minmax(0, 1fr); } }

.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px; min-width: 0; }
.card h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 8px; font-weight: 650; }
.card-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.card-head h2 { margin: 0; }
details.card > summary { list-style: none; cursor: pointer; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
details.card > summary h2 { margin: 0; }
details.card > summary::before { content: "▸"; color: var(--muted); }
details.card[open] > summary::before { content: "▾"; }

.intro h1 { font-size: 28px; line-height: 1.2; letter-spacing: -.02em; margin: 4px 0 16px; }
.eyebrow { margin: 0; color: var(--accent); font-weight: 600; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; }
.steps { padding-left: 20px; margin: 0 0 22px; display: grid; gap: 6px; }
.note { color: var(--muted); font-size: 13px; margin: 14px 0 0; }
.note.warn { color: var(--warn); background: var(--warn-bg); padding: 8px 10px; border-radius: 8px; margin: 0 0 8px; }
.hint { color: var(--muted); font-size: 13px; margin: 0 0 10px; overflow-wrap: anywhere; }
.tag { font-size: 11px; background: var(--surface-2); color: var(--muted); padding: 1px 6px; border-radius: 99px; text-transform: none; letter-spacing: 0; }

.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font-size: 12px; padding: 2px 9px; border-radius: 99px; background: var(--surface-2); color: var(--muted); }
.chip.good { background: var(--good-bg); color: var(--good); }
.chip.bad { background: var(--bad-bg); color: var(--bad); }
.chip.warn { background: var(--warn-bg); color: var(--warn); }

.blocks { display: grid; gap: 10px; }
.block { border: 1px solid var(--border); border-left: 4px solid var(--atten); border-radius: 8px; overflow: hidden; }
.block.authority { border-left-color: var(--auth); } .block.third { border-left-color: var(--third); }
.block-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; padding: 8px 12px; background: var(--surface-2); font-size: 13px; }
.idx { font-family: var(--mono); font-weight: 700; color: var(--muted); }
.kind { font-weight: 600; }
.block.authority .kind { color: var(--auth); } .block.third .kind { color: var(--third); } .block.attenuation .kind { color: var(--atten); }
.small { font-size: 12px; color: var(--muted); } .rid { margin-left: auto; }
pre.code { margin: 0; padding: 10px 12px; font-size: 13px; line-height: 1.55; overflow-x: auto; white-space: pre; }
details.card pre.code { margin-top: 12px; background: var(--surface-2); border-radius: 8px; }
.http { margin-top: 10px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; min-width: 0; }
.io-bar { display: flex; align-items: center; gap: 2px; padding: 0 8px; background: var(--surface-2); border-bottom: 1px solid var(--border); }
.io-tab { appearance: none; border: 0; background: none; color: var(--muted); font: inherit; font-size: 13px; font-weight: 600;
  padding: 8px 10px; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px;
  display: inline-flex; align-items: center; gap: 6px; }
.io-tab:hover { color: var(--text); }
.io-tab.active { color: var(--text); border-bottom-color: var(--accent); }
.io-bar .ms { margin-left: auto; }
.io-pane { padding: 10px; display: grid; gap: 8px; }
.io-pane[hidden] { display: none; }
.pane-head { display: flex; align-items: center; gap: 8px; }
.pane-head .btn { margin-left: auto; }
.pane-head .hint { margin: 0; }
.http pre.code { background: var(--surface-2); border-radius: 8px; font-size: 12px; max-height: 420px; overflow-y: auto; }
pre.code.wrap { white-space: pre-wrap; word-break: break-all; }
.small-btn { padding: 3px 9px; font-size: 12px; }
.tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); }
.tab { padding: 9px 14px; color: var(--muted); text-decoration: none; font-weight: 600; font-size: 14px;
  border-bottom: 2px solid transparent; margin-bottom: -1px; display: inline-flex; align-items: center; gap: 6px; }
.tab:hover { color: var(--text); }
.tab.active { color: var(--text); border-bottom-color: var(--accent); }
.count { font-size: 11px; background: var(--surface-2); color: var(--muted); padding: 1px 7px; border-radius: 99px; }
.calls { display: grid; gap: 14px; }
.call { scroll-margin-top: 16px; border: 1px solid var(--border); border-radius: 10px; padding: 12px; display: grid; gap: 8px; min-width: 0; }
.call-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.call-head .label { font-weight: 600; }
.seq { font: 600 12px var(--mono); color: var(--muted); }
.call > .detail, .last .detail { color: var(--muted); font-size: 12.5px; font-family: var(--mono); overflow-wrap: anywhere; }
.hint.local { margin: 0; font-style: italic; }
.last { display: grid; gap: 6px; } .last h2 { margin-bottom: 2px; }
.link.small { font-size: 12.5px; color: var(--accent); }
.raw { margin-top: 12px; } .raw summary { cursor: pointer; color: var(--muted); font-size: 13px; }
textarea { width: 100%; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); color: var(--text);
  padding: 8px 10px; font-size: 12.5px; resize: vertical; margin: 8px 0; }

.actions h2:not(:first-child) { margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--border); }
.field { display: flex; align-items: center; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 10px; background: var(--bg); }
.field > span:first-child { padding: 7px 10px; font-size: 13px; color: var(--muted); border-right: 1px solid var(--border); }
.prefix { padding-left: 10px; font-family: var(--mono); font-size: 13px; color: var(--muted); }
.field input { flex: 1; min-width: 0; border: 0; background: transparent; color: var(--text); padding: 7px 4px; font: 13px var(--mono); outline: none; }
.row { display: flex; gap: 8px; } .row.wrap { flex-wrap: wrap; }
.btn { appearance: none; border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 8px;
  padding: 7px 12px; font: inherit; font-size: 13.5px; font-weight: 550; cursor: pointer; text-decoration: none; display: inline-block; }
.btn:hover:not([disabled]) { border-color: var(--muted); }
.btn[disabled] { opacity: .45; cursor: not-allowed; }
.btn.primary, .btn.accent { background: var(--accent); color: var(--accent-text); border-color: var(--accent); }
.btn.danger { color: var(--bad); }
.btn.big { padding: 11px 18px; font-size: 15px; }
.row .btn { flex: 1; }

.pill { font: 600 11px var(--mono); padding: 2px 7px; border-radius: 6px; min-width: 44px; text-align: center; }
.pill.good { background: var(--good-bg); color: var(--good); } .pill.bad { background: var(--bad-bg); color: var(--bad); }
"#;

#[cfg(test)]
mod tests {
    use super::{activity_log, esc, last_result};
    use crate::{Event, HttpTrace};

    #[test]
    fn every_activity_row_shows_request_and_response() {
        let trace = HttpTrace {
            curl: "curl -X POST 'http://127.0.0.1:8091/orders/123' -H 'Authorization: Bearer <b>'".into(),
            status: "403 Forbidden".into(),
            elapsed_ms: 3,
            response: r#"{"allowed": false}"#.into(),
        };
        let events = [Event {
            label: "POST /orders/123".into(),
            ok: false,
            status: "403".into(),
            detail: "write requires step-up".into(),
            trace: Some(trace),
        }, Event {
            label: "Attenuate: read-only".into(),
            ok: true,
            status: "ok".into(),
            detail: r#"check if operation("read")"#.into(),
            trace: None,
        }];
        let html = activity_log(&events);
        // Request / Response tabs, Request selected, each with its own copy target.
        assert!(!html.contains("<details"));
        assert!(html.contains(r#"data-pane="event-0-req""#) && html.contains(r#"data-pane="event-0-resp""#));
        assert!(html.contains(r#"<div class="io-pane" id="event-0-req" role="tabpanel">"#));
        assert!(html.contains(r#"<div class="io-pane" id="event-0-resp" role="tabpanel" hidden>"#));
        assert!(html.contains(r#"data-copy="event-0-req-text">Copy curl"#));
        assert!(html.contains(r#"data-copy="event-0-resp-text">Copy response"#));
        assert!(html.contains(r#"id="event-0-req-text""#) && html.contains(r#"id="event-0-resp-text""#));
        assert!(html.contains(&esc("Bearer <b>")), "token must be HTML-escaped");
        assert!(html.contains("403 Forbidden"));
        assert!(html.contains(&esc(r#"{"allowed": false}"#)));
        assert!(!html.contains("CLIENT_SECRET"), "no secret note for orders-api calls");
        assert!(html.contains("No HTTP call"), "local actions say so");
        assert!(html.contains("#2") && html.contains("#1"), "rows are numbered");

        // Oldest first: #1 is the POST, #2 (the newest, at the bottom) is the anchor target.
        assert!(html.find("#1").unwrap() < html.find("#2").unwrap());
        assert!(html.contains(r#"<article class="call" id="latest">"#));
        let last = last_result(&events);
        assert!(last.contains("Attenuate: read-only"), "sidebar shows the newest event");
        assert!(!last.contains("?tab=activity"), "no HTTP call, so no link to one");
        let last_http = last_result(&events[..1]);
        assert!(last_http.contains("POST /orders/123") && last_http.contains("?tab=activity#latest"));
    }
}
