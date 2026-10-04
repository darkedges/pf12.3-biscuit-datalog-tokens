---
title: >-
  Configuring PingFederate token exchange with Terraform, and testing it end to
  end
published: false
description: >-
  17 Terraform resources take a blank PingFederate to HTML form login, JWT
  access tokens and a JWT-to-Biscuit token exchange. Two of them need the
  generic restapi provider. Then a demo app that shows every request and
  response.
tags: 'pingfederate, terraform, oauth, rust'
series: Biscuit meets PingFederate
cover_image: null
canonical_url: null
devto: true
devto_id: 4795597
---

*Repo: [darkedges/pf12.3-biscuit-datalog-tokens](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens)*

Part 2 built a token generator plugin. On its own it does nothing: PingFederate needs a login, an access token manager, a client, a processor policy, a generator instance, a generator group and a mapping between them before a single Biscuit comes out.

This part configures all of that with Terraform, then runs the full flow in a browser: log in, exchange, call an API, get refused, and see why.

## 1. The stack

[`docker-compose.yaml`](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens/blob/main/docker-compose.yaml) runs two things:

- **`pingfederate`**: PingFederate 12.3.3 with the getting-started server profile, built from the multi-stage Dockerfile from Part 2, so the plugin is already deployed.
- **`terraform`**: a `hashicorp/terraform` container in a `tools` profile. It reaches the admin API at `https://pingfederate:9999` on the compose network, so you don't need Terraform on your machine.

Everything runs through `make`:

```bash
make up          # build the image (plugin compiled and tested inside Docker) and start PingFederate
make tf-plan     # generate the Biscuit root key once, init, plan → terraform/tfplan
make tf-apply    # apply the saved plan
make tf-creds    # generated passwords for alice and bob, and the client secret
make web         # orders-api + the demo web app, prints "Ready" when 8090 is listening
```

## 2. What Terraform creates

Seventeen resources take a blank PingFederate to a working token exchange:

| Piece | Resource |
|---|---|
| Demo users `alice` and `bob`, with generated passwords | `random_password` + `pingfederate_password_credential_validator` |
| HTML form login | `pingfederate_idp_adapter` + `pingfederate_oauth_idp_adapter_mapping` |
| Scopes `orders:read`, `orders:write` | `pingfederate_oauth_server_settings` |
| JWT access tokens carrying `username` | `pingfederate_oauth_access_token_manager` + `pingfederate_oauth_access_token_mapping` |
| Client `orders-web`: authorization code, refresh token, token exchange | `pingfederate_oauth_client` |
| Validates the incoming JWT | `pingfederate_idp_token_processor` |
| Picks `subject`, `client_id`, `scope` | `pingfederate_oauth_token_exchange_processor_policy` |
| **The Biscuit generator instance** | `restapi_object` → `/sp/tokenGenerators` |
| **Routes the Biscuit token type to it** | `restapi_object` → `/oauth/tokenExchange/generator/groups` |
| Policy attributes → generator contract | `pingfederate_oauth_token_exchange_token_generator_mapping` |
| Makes that group the default | `pingfederate_oauth_token_exchange_generator_settings` |

The token exchange pipeline from Part 1 maps directly onto the last six rows.

### Validating the subject token

The processor is PingFederate's built-in `BearerAccessTokenTokenProcessor`, pointed at the **same access token manager that issued the JWT**. PingFederate validates its own tokens, with no JWKS plumbing:

```hcl
resource "pingfederate_idp_token_processor" "access_token" {
  processor_id = "biscuitAccessTokenProcessor"
  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor"
  }
  configuration = {
    fields = [
      { name = "Access Token Manager", value = pingfederate_oauth_access_token_manager.jwt.manager_id },
      { name = "Scope value as single string", value = "true" },
    ]
  }
  # core: aud, authorization_details, client_id, expires_at, iss, scope; extended: username
}
```

The processor's core contract has `client_id` and `scope`, but **not** the user. The user arrives as the extended attribute `username`, which has to match the access token manager's contract.

### The processor policy: what PingFederate lets through

This is the governance point from Part 1. The policy chooses which attributes go to the generator. This is where you'd add issuance criteria, such as "only this client" or "only if the token has this scope":

```hcl
resource "pingfederate_oauth_token_exchange_processor_policy" "biscuit" {
  policy_id = "biscuitExchange"
  name      = "Access token to Biscuit"
  # "subject" is a built-in core attribute of every processor policy.
  attribute_contract = {
    extended_attributes = [{ name = "client_id" }, { name = "scope" }]
  }
  processor_mappings = [{
    subject_token_type      = "urn:ietf:params:oauth:token-type:access_token"
    subject_token_processor = { id = pingfederate_idp_token_processor.access_token.processor_id }
    attribute_contract_fulfillment = {
      subject   = { source = { type = "SUBJECT_TOKEN" }, value = "username" }
      client_id = { source = { type = "SUBJECT_TOKEN" }, value = "client_id" }
      scope     = { source = { type = "SUBJECT_TOKEN" }, value = "scope" }
    }
  }]
}
```

(The comment is there because I tried to declare `subject` myself, and the provider refuses: it's read-only.)

## 3. The provider gap: `restapi` for two objects

The PingFederate Terraform provider (1.10.0, the latest at the time of writing) has no resource for **SP token generators** or **token exchange generator groups**. Those are exactly the two objects this project needs.

Rather than shell out to scripts, I used the generic [`Mastercard/restapi`](https://registry.terraform.io/providers/Mastercard/restapi/latest) provider against the admin API. Those objects still go through plan, apply and destroy like everything else. Abridged from [`token_exchange.tf`](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens/blob/main/terraform/token_exchange.tf), where the literals are variables:

```hcl
resource "restapi_object" "biscuit_generator" {
  path      = "/sp/tokenGenerators"
  object_id = "biscuit"
  data = jsonencode({
    id                  = "biscuit"
    name                = "Biscuit token generator"
    pluginDescriptorRef = { id = "com.darkedges.pingfederate.biscuit.BiscuitTokenGenerator" }
    configuration = { fields = [
      { name = "Root Private Key", value = var.biscuit_root_private_key },
      { name = "Root Key ID", value = "1" },
      { name = "Issuer", value = var.pf_runtime_url },
      { name = "Token Lifetime (seconds)", value = "300" },
      { name = "Audiences", value = "orders-api" },
      { name = "Fact Attributes", value = "subject,client_id,scope" },
    ] }
    attributeContract = {
      coreAttributes     = [{ name = "subject" }]
      extendedAttributes = [{ name = "client_id" }, { name = "scope" }]
    }
  })
  ignore_server_additions = true
  ignore_changes_to       = ["configuration.fields", "attributeContract.extendedAttributes"]
}
```

Those last two lines took three plans to get right. After the first apply, every plan showed both objects changed, because PingFederate *adds* things:

- `location` and `lastModified` fields;
- an empty `resourceUris` list on the group;
- the private key returned as `encryptedValue` instead of `value`;
- extended attributes in a different order.

`ignore_server_additions` ignores fields the server adds but still detects changes to fields you set. Now a plan straight after an apply says **No changes**, and editing the Terraform still triggers an update.

The generator group is the piece that makes `requested_token_type` work:

```hcl
resource "restapi_object" "biscuit_generator_group" {
  path      = "/oauth/tokenExchange/generator/groups"
  object_id = "biscuit"
  data = jsonencode({
    id   = "biscuit"
    name = "Biscuit"
    generatorMappings = [{
      requestedTokenType = "urn:darkedges:params:oauth:token-type:biscuit"
      tokenGenerator     = { id = restapi_object.biscuit_generator.object_id }
      defaultMapping     = true
    }]
  })
  ignore_server_additions = true
}
```

## 4. Smaller things worth knowing

- **The root key is generated by the plugin itself.** `make tf-plan` runs the plugin jar's `keygen` *inside the PingFederate container*, so you don't need a JDK. It writes the result to a git-ignored `terraform/biscuit.auto.tfvars`. Terraform passes the private key to PingFederate, and the services get the public key.
- **The JWT symmetric key must be hex.** With the access token manager's "Encoding" field left blank, PingFederate expects the HS256 key as hex. My first apply failed with `Key with key id 'k1' is not valid hex`, and `random_bytes.hex` fixed it.
- **Generated secrets live in Terraform state.** Demo passwords, the client secret and the JWT key are `random_*` resources. That's fine for a lab, but in production you'd source them from a vault.
- **Destroy is clean.** `make tf-destroy` removes all 17 resources in dependency order. PingFederate clears the default generator group reference itself when the group goes.

## 5. Testing it end to end

With PingFederate running and Terraform applied, `make web` starts two things: `orders-api` (Rust, biscuit-auth 6) on port 8091, and the demo web app on port 8090. It prints a "Ready" line only once both are listening.

Open `http://localhost:8090` and log in as `alice`, with the password from `make tf-creds`. The app runs a standard authorization code flow against PingFederate's HTML form, then does the token exchange. The **Token** tab shows the Biscuit PingFederate minted:

```datalog
issuer("https://localhost:9031");
user("alice");
client("orders-web");
scope("orders:read");
scope("orders:write");
check if time($t), $t <= 2026-10-04T11:23:13Z;
check if audience($a), {"orders-api"}.contains($a);
```

It's labelled *authority · minted by PingFederate* and marked *signature verified* against PingFederate's public key.

The **HTTP activity** tab lists every call in order, each with **Request / Response** tabs. The request is a runnable curl with **Copy curl**, and the response is the JSON with **Copy response**:

| # | Call | Result |
|---|---|---|
| 1 | Authorization code → access token (JWT) | `200`, `token_type=Bearer`, `expires_in=3599` |
| 2 | Token exchange: JWT → Biscuit | `200`, `issued_token_type=…:biscuit`, `token_type=N_A`, `expires_in=299` |
| 3 | `GET /orders/123` with the Biscuit | `200`, `{"allowed": true, "user": "alice"}` |
| 4 | `POST /orders/123` with the Biscuit | `403`, `write requires amr("mfa") signed by ed25519/59c0… (step-up)` |

Call 3 shows the point of the whole design: **orders-api didn't call PingFederate.** It verified the signature with the public key, added facts about the request (`operation("read")`, `resource("/orders/123")`, `audience("orders-api")`, the time), and evaluated its policy locally.

Call 4 is the cliffhanger. Alice has `orders:write`, but the policy also wants proof of MFA, as a block signed by a key PingFederate controls. That's Part 4.

### Without a browser

The same flow runs from the command line, which is handy for CI or for seeing the raw calls:

```bash
make auto-login LOGIN_USER=bob   # fills in PingFederate's HTML form with curl
make exchange                    # JWT → Biscuit, prints its Datalog
make api-pf                      # orders-api in another terminal
make call                        # GET → 200, POST → 403
```

## Next

In Part 4 we unlock that write: a step-up MFA attestation appended as a third-party block, then attenuation and sealing in the demo app. Then the honest part: what this design doesn't solve yet, and the library gap that stops PingFederate from being the attestor today.
