# pf12.3-biscuit-token-exchange

PingFederate 12.3 token generator plugin that mints [Biscuit](https://www.biscuitsec.org/) (Datalog) capability tokens through OAuth token exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)). It comes with Terraform config, a Rust resource server, and a demo web app for attenuation and step-up MFA.

Users log in with PingFederate as usual and get a JWT. The client exchanges that JWT at PingFederate for a **Biscuit** signed with PingFederate's key. From then on, services:

- **verify** the Biscuit offline with only PingFederate's public key;
- **authorize** with Datalog policies;
- **narrow** it themselves (read-only, one resource, shorter lifetime), with no call back to PingFederate.

> This is a prototype for exploring the idea. It uses demo users, generated secrets in local Terraform state, self-signed TLS and a simulated MFA attestor (see [Findings](#findings)). Don't run it as-is in production.

---

## Contents

1. [How it works](#how-it-works)
2. [Repository layout](#repository-layout)
3. [Prerequisites](#prerequisites)
4. [Step-by-step: deploy and test](#step-by-step-deploy-and-test)
5. [Using the web app](#using-the-web-app)
6. [Command-line flow](#command-line-flow)
7. [What gets deployed](#what-gets-deployed)
8. [Configuration reference](#configuration-reference)
9. [Make targets](#make-targets)
10. [Troubleshooting](#troubleshooting)
11. [Findings](#findings)

---

## How it works

```
 Browser                demo-web :8090              PingFederate :9031             orders-api :8091
    │  log in               │                             │                              │
    ├──────────────────────▶│ ── authorize (HTML form) ──▶│                              │
    │                       │ ◀── code ───────────────────│                              │
    │                       │ ── code → JWT ─────────────▶│  JWT access token            │
    │                       │ ── token exchange ─────────▶│  Biscuit Token Generator     │
    │                       │    (JWT → Biscuit)          │  (this plugin, Ed25519 key)  │
    │                       │ ◀── Biscuit ────────────────│                              │
    │                       │                                                            │
    │  GET/POST, attenuate, │ ── Authorization: Bearer <Biscuit> ───────────────────────▶│
    │  step up, seal        │    (blocks appended locally, no PingFederate call)         │ verify with PF public key
    │                       │ ◀── 200 / 403 + reason ────────────────────────────────────│ + Datalog policy
```

The Biscuit's first block, the **authority block**, is minted by PingFederate from the token exchange attributes:

```datalog
issuer("https://localhost:9031");
user("alice");
client("orders-web");
scope("orders:read");
scope("orders:write");
check if time($t), $t <= 2026-10-04T11:23:13Z;
check if audience($a), {"orders-api"}.contains($a);
```

After that, anyone holding the token can append blocks, but appended blocks can only **narrow** what it allows:

```datalog
check if operation("read");                        // read-only
check if resource($r), $r == "/orders/123";        // one order
```

orders-api adds facts describing the current request (`time`, `audience`, `operation`, `resource`) and evaluates its policy:

```datalog
allow if scope("orders:read"), operation("read");
allow if scope("orders:write"), operation("write"), amr("mfa") trusting authority, ed25519/<attestation key>;
deny if true;
```

So a write needs the `orders:write` scope **and** an MFA attestation, as a block signed by the attestation key.

## Repository layout

| Path | What it is |
|---|---|
| `pf-biscuit-generator/` | The PingFederate **Token Generator** plugin (SDK 12.3.3, Java 11, biscuit-java 4.0.1, dependencies shaded). The jar is also a CLI: `keygen`, `mint`, `attest`. |
| `docker/pingfederate/Dockerfile` | Multi-stage build: compiles the plugin against the SDK jars inside the PingFederate image, then puts it in `/opt/server/server/default/deploy/`. |
| `docker-compose.yaml` | PingFederate 12.3.3 (getting-started server profile) plus a `terraform` tools container. |
| `terraform/` | PingFederate config: demo users, HTML form login, JWT access tokens, OAuth client, token exchange to Biscuit. |
| `orders-api/` | Rust resource server (biscuit-auth 6) that authorizes every request offline. Also builds `hop`, a CLI for token holders: `inspect`, `attenuate`, `seal`, `request`, `append`, `attest`, `keygen`. |
| `demo-web/` | Browser app: PingFederate login, token exchange, calls to orders-api, step-up, attenuation and sealing. Every HTTP call is shown as a runnable curl plus its JSON response. |
| `scripts/demo.sh` | Standalone end-to-end check (19 assertions) that needs no PingFederate. |
| `scripts/pf-flow.sh` | The command-line flow against a real PingFederate (`make login / token / exchange / mfa / call`). |
| `Makefile` | Wraps all of the above; `make` lists the targets. |

## Prerequisites

| Tool | Needed for | Notes |
|---|---|---|
| Docker with Compose **v2.17+** | PingFederate, the image build, Terraform | `additional_contexts` needs v2.17 or later |
| Ping Identity **DevOps credentials** | PingFederate's evaluation license | Free; see [Ping's DevOps registration](https://devops.pingidentity.com/how-to/devopsRegistration/) |
| GNU **make** and **bash** | All targets | On Windows, use [Git for Windows](https://gitforwindows.org/) and make (e.g. `choco install make`). The Makefile runs recipes with Git Bash even when started from PowerShell. |
| **Rust** (stable, via rustup) | orders-api, hop, demo-web | |
| **curl**, **python 3** | `scripts/pf-flow.sh`, `make web` | |
| **JDK 11+** and **Maven 3.8+** | Optional: building the plugin on the host, `make demo`, `make test` | Not needed for the Docker build, which uses its own JDK 11 |

Free ports on the host: **9999** (PingFederate admin), **9031** (PingFederate runtime), **8090** (web app) and **8091** (orders-api). The last two can be changed; see [Configuration reference](#configuration-reference).

## Step-by-step: deploy and test

### 1. Clone and add your DevOps credentials

```bash
git clone <this repo> pf12.3-biscuit-token-exchange
cd pf12.3-biscuit-token-exchange
cat > .env <<'EOF'
PING_IDENTITY_DEVOPS_USER=you@example.com
PING_IDENTITY_DEVOPS_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
EOF
```

`.env` is git-ignored. Docker Compose reads it automatically.

### 2. (Optional) Run the standalone check

This needs JDK 11+ and Maven, but no PingFederate. It runs the plugin's minting code directly, then exercises attenuation, step-up, sealing, certificate binding and revocation against orders-api:

```bash
make demo
```

Expected: `19 passed, 0 failed`. If your default `java` is older than 11, create `local.mk` with `JAVA_HOME := /path/to/jdk-11`.

### 3. Build the PingFederate image and start it

```bash
make up
```

This builds `pingfedonetap/pingfederate:2511-12.3.3`: Maven compiles and tests the plugin inside Docker, and the jar lands in `/opt/server/server/default/deploy/`. It then starts the `pingfederate-xaa` container. The first start takes a few minutes. Follow it with:

```bash
make logs          # Ctrl+C to stop following
make ps            # wait for "(healthy)"
```

**Check:** the admin console at https://localhost:9999/pingfederate/app (getting-started login: `administrator` / `2FederateM0re`) opens. Accept the self-signed certificate. The plugin should appear as **Biscuit Token Generator** among the available token generator types.

### 4. Plan the PingFederate configuration

```bash
make tf-plan
```

The first time, this:

1. generates the Biscuit **root key pair** with the plugin's own `keygen`, inside the container, into `terraform/biscuit.auto.tfvars` (git-ignored);
2. runs `terraform init` in the `terraform` container;
3. plans the configuration and saves it to `terraform/tfplan`.

Expected: `Plan: 17 to add, 0 to change, 0 to destroy.`

### 5. Apply it

```bash
make tf-apply
```

Expected: `Apply complete! Resources: 17 added, 0 changed, 0 destroyed.`

**Check:** run `make tf-plan` again. It should say `No changes. Your infrastructure matches the configuration.`

### 6. Get the demo credentials

```bash
make tf-creds
```

This prints the generated passwords for `alice` and `bob`, and the `orders-web` client secret.

### 7. Start the web app

```bash
make web
```

This builds and starts orders-api on **:8091** and demo-web on **:8090**, waits until both are listening, then prints:

```
  Ready: http://localhost:8090   (orders-api on :8091; Ctrl+C stops both)
```

If PingFederate is still starting, it first waits (`waiting for PingFederate on https://localhost:9031 ....... up`). If a port is taken, it names the container using it. The first run also generates the simulated MFA attestation key into `.keys/attestation.env` (git-ignored).

### 8. Test it in the browser

Open http://localhost:8090. Before the first login, open https://localhost:9031 once and accept its certificate.

1. **Log in with PingFederate**: use `alice` and her password from step 6. You land back on the app with a Biscuit. The **Token** tab shows its authority block marked *signature verified*, and the **Token exchange (RFC 8693)** panel shows the request and PingFederate's reply: `issued_token_type=urn:darkedges:params:oauth:token-type:biscuit`, `token_type=N_A`, `expires_in=299`.
2. **GET · read**: the app switches to the **HTTP activity** tab. Expect **200** `{"allowed":true,"user":"alice",...}`.
3. **POST · write**: expect **403** with `write requires amr("mfa") signed by ed25519/… (step-up)`.
4. **Add MFA attestation**: the Token tab now shows a *third-party · attestation* block containing `amr("mfa")`.
5. **POST · write** again: expect **200**.
6. **Read-only**: an attenuation block appears with `check if operation("read")`. POST now returns **403**, naming the failed check.
7. **Only this order** with order `999`: GET `/orders/999` returns 200 and GET `/orders/123` returns 403.
8. **Seal**: the attenuation buttons are disabled. Use **Fresh Biscuit from PingFederate** to start over.

In **HTTP activity**, each call has **Request / Response** tabs. Request shows a runnable curl with **Copy curl**; Response shows the status, timing and JSON with **Copy response**. PingFederate calls show the client secret as `$CLIENT_SECRET`; export it from step 6 to re-run them.

### 9. (Optional) Test from the command line

See [Command-line flow](#command-line-flow).

### 10. Tear down

```bash
make tf-destroy    # remove the 17 Terraform-managed objects from PingFederate
make down          # stop PingFederate; keeps the volume
make reset         # stop PingFederate and delete its volume (wipes all PingFederate config)
```

## Using the web app

| Area | What it does |
|---|---|
| **Token** tab | The Biscuit, block by block: authority (PingFederate), third-party (attestation), attenuations. Each block shows its Datalog and revocation ID. Also shows size, signature status, the raw token, the token exchange request/response, and the decoded JWT. |
| **HTTP activity** tab | Every call oldest-first: authorization code → JWT, token exchange, orders-api calls. Each has Request / Response tabs with copy buttons. Local actions (attenuate, seal, step-up) are listed too, marked *No HTTP call*. After a call the page jumps to the newest entry. |
| **Call orders-api** | `GET` (read) or `POST` (write) on `/orders/{id}`. The order ID accepts 1–32 letters, digits, `-` and `_`. |
| **Step up** | Appends `amr("mfa")` as a third-party block signed by the attestation key. |
| **Attenuate** | Read-only, only this order, expire in 60 s, or your own Datalog block. Values go in as Datalog parameters, never pasted into the source. |
| **Seal** | Blocks any further appends. |
| **Fresh Biscuit** | Re-runs the token exchange with the session's JWT. |
| **Last result** | The latest outcome, with a link to its request and response. |

## Command-line flow

The same flow, driven by `scripts/pf-flow.sh`. Tokens are cached in `.flow/`.

```bash
make login                       # prints the authorize URL; log in, then copy ?code=… from the address bar
make token CODE=<code>           # authorization code → JWT (prints its claims)
#   or, without a browser:
make auto-login LOGIN_USER=bob   # fills in the HTML form with curl, then gets the JWT

make exchange                    # JWT → Biscuit (prints its Datalog)
make api-pf                      # in another terminal: orders-api trusting PingFederate's keys
make call                        # GET → 200, POST → 403 "write requires amr("mfa") ... (step-up)"
make mfa                         # append amr("mfa") signed by the attestation key
make call                        # POST → 200
make flow-reset                  # clear .flow/
```

The raw token exchange request:

```bash
curl -k -X POST 'https://localhost:9031/as/token.oauth2' \
  -u "orders-web:$CLIENT_SECRET" \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$JWT" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'requested_token_type=urn:darkedges:params:oauth:token-type:biscuit'
```

```json
{
  "access_token": "CAESiwMKoAIKBmlzc3Vlcg…",
  "issued_token_type": "urn:darkedges:params:oauth:token-type:biscuit",
  "token_type": "N_A",
  "expires_in": 299
}
```

The `access_token` is the Biscuit in its native base64url form. `hop` works with it directly:

```bash
orders-api/target/debug/hop inspect "$(cat .flow/biscuit)"
orders-api/target/debug/hop attenuate "$(cat .flow/biscuit)" 'check if operation("read");'
```

## What gets deployed

### The plugin

`com.darkedges.pingfederate.biscuit.BiscuitTokenGenerator` implements PingFederate's `TokenGenerator` SDK interface:
- **Token type:** `urn:darkedges:params:oauth:token-type:biscuit`
- **Core contract:** `subject`, with extended attributes allowed.

| Setting | Meaning | Terraform default |
|---|---|---|
| Root Private Key | Hex Ed25519 private key that signs the authority block (encrypted field) | from `biscuit.auto.tfvars` |
| Root Key ID | Written into the token so verifiers can pick the right key during rotation | `1` |
| Issuer | Becomes the `issuer(...)` fact | `https://localhost:9031` |
| Token Lifetime (seconds) | Becomes `check if time($t), $t <= now + lifetime` | `300` |
| Audiences | Becomes `check if audience($a), {...}.contains($a)` | `orders-api` |
| Fact Attributes | Contract attributes that become facts (`subject`→`user`, `client_id`→`client`) | `subject,client_id,scope` |

How it maps attributes:
- **Scope:** a space-separated `scope` value becomes one `scope(...)` fact per scope.
- **Certificate binding:** a `cnf_x5t_s256` attribute adds `check if tls_client_cert_sha256($c), $c == "<thumbprint>"`.
- **Revocation logging:** every mint logs the subject, the expiry and the authority block's revocation ID.

### Terraform (`terraform/`, 17 resources)

| Piece | Resource |
|---|---|
| Demo users `alice`, `bob` with generated passwords | `random_password` + `pingfederate_password_credential_validator` (simple username/password) |
| HTML form login | `pingfederate_idp_adapter` + `pingfederate_oauth_idp_adapter_mapping` |
| Scopes `orders:read`, `orders:write` | `pingfederate_oauth_server_settings` |
| JWT access tokens (HS256) carrying `username` | `pingfederate_oauth_access_token_manager` + `pingfederate_oauth_access_token_mapping` |
| Client `orders-web` (authorization code, refresh, token exchange) | `pingfederate_oauth_client` |
| Validates the subject JWT | `pingfederate_idp_token_processor` (`BearerAccessTokenTokenProcessor`) |
| `subject` / `client_id` / `scope` from the JWT | `pingfederate_oauth_token_exchange_processor_policy` |
| The Biscuit generator instance | `restapi_object` → `/sp/tokenGenerators` |
| Requested token type → generator | `restapi_object` → `/oauth/tokenExchange/generator/groups`, set as the default group |
| Policy attributes → Biscuit contract | `pingfederate_oauth_token_exchange_token_generator_mapping` |

Providers: `pingidentity/pingfederate` 1.10.0, `Mastercard/restapi` 3.0.0, `hashicorp/random` 3.9.1.
- **Why restapi:** the pingfederate provider has no resources for SP token generators or generator groups, so those two use `restapi`.
- **No false drift:** `ignore_server_additions` stops fields that PingFederate adds itself (`location`, `lastModified`, the encrypted key) from showing up as changes.

### Keys and secrets (all git-ignored)

| File | Contents |
|---|---|
| `terraform/biscuit.auto.tfvars` | Biscuit root private and public key |
| `.keys/attestation.env` | Simulated PingFederate MFA attestation key pair |
| `terraform/terraform.tfstate` | Generated passwords, client secret, JWT signing key |
| `.env` | Ping DevOps credentials |
| `local.mk` | Machine-specific make settings |
| `.flow/` | Command-line flow cache (JWT, Biscuit, client settings) |

## Configuration reference

### Make variables (pass on the command line, e.g. `make web WEB_PORT=8095`, or put them in `local.mk`)

| Variable | Default | Purpose |
|---|---|---|
| `WEB_PORT` | `8090` | Web app port. Must match `redirect_uris` in Terraform. |
| `API_PORT` | `8091` | orders-api port |
| `PF_RUNTIME` | `https://localhost:9031` | PingFederate runtime URL that `make web` waits for |
| `SKIP_TESTS` | `false` | Skip plugin tests in `make plugin` / `make image` |
| `LOGIN_USER` | `alice` | User for `make auto-login` |
| `CODE` | | Authorization code for `make token` |
| `PATH_` | `/orders/123` | Path for `make call` |
| `LINES`, `LOG` | `200`, `server.log` | `make logs` / `make log-file` |
| `JAVA_HOME` | | JDK 11+ for host builds |
| `GIT_BASH` | `C:/PROGRA~1/Git/bin/bash.exe` | Windows only: the shell make uses for recipes |

### Compose / environment (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `PING_IDENTITY_DEVOPS_USER`, `PING_IDENTITY_DEVOPS_KEY` | | Required: PingFederate license |
| `PF_ADMIN_USER`, `PF_ADMIN_PASSWORD` | `administrator` / `2FederateM0re` | Admin API credentials Terraform uses |
| `PINGFEDERATE_IMAGE_TAG` | `2511-12.3.3` | Base PingFederate image; the SDK jars are taken from the same image |
| `TERRAFORM_IMAGE_TAG` | `1.16` | `hashicorp/terraform` image |
| `DATALOG_SUBNET` | `10.231.0.0/24` | Docker network subnet, pinned because the default address pools can run out |

### Terraform variables (`terraform/variables.tf`)

| Variable | Default |
|---|---|
| `demo_users` | `["alice", "bob"]` |
| `client_id` | `orders-web` |
| `redirect_uris` | `["http://localhost:8090/callback"]` |
| `scopes` | `orders:read`, `orders:write` |
| `biscuit_audiences` | `["orders-api"]` |
| `biscuit_lifetime_seconds` | `300` |
| `biscuit_root_key_id` | `1` |
| `pf_runtime_url` | `https://localhost:9031` |

## Make targets

Run `make` for the full list. The main groups:

| Group | Targets |
|---|---|
| Build | `plugin`, `api`, `demo-web`, `build` |
| Test | `test-plugin`, `test-api`, `test`, `demo`, `keygen` |
| PingFederate | `image`, `up`, `down`, `reset`, `restart`, `redeploy`, `logs`, `log-file`, `ps`, `shell` |
| Terraform | `tf-keys`, `tf-init`, `tf-validate`, `tf-fmt`, `tf-plan`, `tf-apply`, `tf-destroy`, `tf-output`, `tf-creds` |
| Demo flow | `web`, `attest-keys`, `login`, `token`, `auto-login`, `exchange`, `mfa`, `api-pf`, `call`, `flow-reset` |
| Housekeeping | `clean` |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `all predefined address pools have been fully subnetted` | Docker has run out of default subnets. The compose file pins `10.231.0.0/24`; set `DATALOG_SUBNET` if that clashes with your network, or run `docker network prune`. |
| `port 8091 is already in use by container …` | Another project publishes that port. Use `make web API_PORT=<free port>`. To change `WEB_PORT`, also change Terraform's `redirect_uris` and re-apply. |
| `PingFederate is not running; start it with make up` | The container is stopped. Run `make up`, then `make web` again. |
| Login page won't load / certificate error | Open https://localhost:9031 once and accept the self-signed certificate. |
| A rebuilt plugin isn't picked up | PingFederate copies `/opt/server` into its `/opt/out` volume only on a fresh start. Run `make redeploy`, which wipes the volume, then `make tf-plan tf-apply` again. If Terraform errors on missing objects, delete `terraform/terraform.tfstate` first; the Biscuit key is kept. |
| `Access is denied (os error 5)` while building on Windows | A running `orders-api.exe` or `demo-web.exe` is locking the file. Stop `make web` / `make api-pf` first. |
| Host plugin tests fail on JDK 17+ with `InaccessibleObjectException` | The SDK test bootstraps PingFederate internals that need `--add-opens` on 17+. Use JDK 11 (`JAVA_HOME` in `local.mk`). The Docker build already does. |
| `'JAVA_HOME' is not recognized…` from PowerShell | Install Git for Windows; the Makefile runs its recipes with Git Bash. If Git lives elsewhere, set `GIT_BASH` in `local.mk`. |
| POST returns 403 `write requires amr("mfa") …` | Working as intended: click **Add MFA attestation** (or run `make mfa`) first. |

## Findings

**What works**
- **Interoperability:** biscuit-java 4.0.1 tokens minted in PingFederate verify in biscuit-auth 6 (Rust) using only the public key.
- **Unchanged pass-through:** PingFederate's token exchange endpoint returns `BinarySecurityToken.getEncodedData()` unchanged as `access_token`, sets `token_type=N_A`, and computes `expires_in` from the expiry date the plugin sets. The Biscuit therefore leaves PingFederate in its native base64url form.
- **Offline attenuation:** narrowing needs neither the root key nor a round-trip to PingFederate. A holder can't widen a token: an `amr("mfa")` or `scope(...)` it adds itself is ignored.
- **Sealing, certificate binding and revocation work:** revoking the authority block's ID kills every narrowed copy.

**Design rules the code enforces**
- **No Datalog injection.** Attribute values become string terms through the builder API and are never concatenated into Datalog source. This is tested.
- **Token facts never shadow request facts.** Authority facts are trusted as much as the authorizer's own, so an attribute that became `operation("write")` would grant writes. The minter therefore refuses the fact names services supply: `time`, `operation`, `resource`, `audience`, `tls_client_cert_sha256`, `issuer`, `hop`. Treat the fact vocabulary as a versioned contract between PingFederate and your services.

**Gotchas**
- **`trusting` replaces the default scope.** `allow if scope("w"), amr("mfa") trusting ed25519/<key>` silently stops seeing authority facts; write `trusting authority, ed25519/<key>`.
- **PingFederate can't sign attestations yet.** biscuit-java 4.0.1 uses the legacy third-party request format (`previousKey`), while biscuit-auth 6 sends `previous_signature` and rejects the legacy one (`Message missing required fields: previousKey`). The demo therefore simulates PingFederate's attestor with a separate key. A real one needs biscuit-java to catch up, or a sidecar.
- **biscuit-java's default 5 ms authorizer budget** can be too short for a cold JVM. Pass `RunLimits` explicitly.
- **biscuit-java drops `root_key_id`** when parsing with a plain public key. Use the `KeyDelegate` overload, which is also how rotation works.
- **Classpath clashes.** PingFederate ships vavr 0.10.2 and its own protobuf, so the plugin shades and relocates all of biscuit-java's dependencies.

**Not covered**
- **Introspection:** PingFederate can't say whether a narrowed token is *authorized*, because it lacks the request context.
- **Revocation lists:** distributing them to services is out of scope; orders-api reads a file.
- **Policy governance:** each service carries its own Datalog policy.
- **Ecosystem:** PingAccess and off-the-shelf gateways don't understand Biscuits, so keep JWTs at the edge and Biscuits between internal services.
