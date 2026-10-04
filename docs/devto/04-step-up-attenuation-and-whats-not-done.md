---
title: 'Step-up MFA, attenuation, and what''s honestly not done'
published: false
description: >-
  Unlocking a write with an MFA attestation block, narrowing and sealing a
  PingFederate-minted Biscuit, and the honest list: a biscuit-java gap,
  revocation distribution, introspection, and what production would need.
tags: 'security, authorization, pingfederate, datalog'
series: Biscuit meets PingFederate
cover_image: null
canonical_url: null
devto: true
devto_id: 4795598
---

*Repo: [darkedges/pf12.3-biscuit-datalog-tokens](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens)*

We've covered why a hybrid works, the token generator plugin, and the Terraform plus end-to-end test. Part 3 ended with alice holding `orders:write` and still getting a `403`. This part unlocks that write, narrows the token in a few ways, and then says plainly what doesn't work yet.

## 1. Why the write was refused

orders-api's policy has three rules:

```datalog
allow if scope("orders:read"), operation("read");
allow if scope("orders:write"), operation("write"), amr("mfa") trusting authority, ed25519/<attestation key>;
deny if true;
```

A write needs the scope **and** an `amr("mfa")` fact. It also has to be a fact the service *trusts*. `trusting authority, ed25519/<key>` means: look for `amr("mfa")` in the authority block (PingFederate's) or in a block signed by the attestation key, and nowhere else.

When no allow rule matches, Biscuit only reports that `deny if true` matched, which tells you nothing. So orders-api works out which requirement is missing and says so:

```json
{
  "allowed": false,
  "operation": "write",
  "reason": "write requires amr(\"mfa\") signed by ed25519/59c06655… (step-up)",
  "resource": "/orders/123"
}
```

### The gotcha in `trusting`

My first version of that rule was:

```datalog
allow if scope("orders:write"), operation("write"), amr("mfa") trusting ed25519/<attestation key>;
```

It never matched, even with the attestation present. `trusting` **replaces** a rule's default scope; it doesn't add to it. Without `authority` in the list, the rule could no longer see `scope("orders:write")` in PingFederate's authority block. It failed silently, with no error. If you write Biscuit policies with third-party blocks, `trusting authority, <key>` is almost always what you mean.

## 2. Step-up: an attestation as a third-party block

Biscuit has a mechanism designed for exactly this: **third-party blocks**. The holder sends a *request* derived from its token to an attestor. The attestor signs a block (here containing `amr("mfa")`) bound to that specific token, and the holder appends it. Nobody else can move that block onto a different token, and the attestor never sees the token itself.

In the demo app, **Add MFA attestation** does exactly that. The Token tab then shows a second block:

```
1  third-party · attestation    signed by ed25519/59c06655…
   amr("mfa");
```

POST again and it's a `200`. From the command line, `make mfa` followed by `make call` does the same.

### The honest part: PingFederate isn't the attestor yet

The design I wanted was **PingFederate signs the attestation**, right after it has run MFA. It has the user's session and knows MFA happened, and it already holds signing keys. biscuit-java even has the API for it.

It doesn't work today. biscuit-java 4.0.1, the latest on Maven Central, still uses the **legacy** third-party request format, which carries a `previousKey`. biscuit-auth 6 (Rust, which orders-api and the demo app use) sends the newer format with a `previous_signature`, and rejects the legacy one. Hand a Rust-made request to biscuit-java and you get:

```
InvalidProtocolBufferException: Message missing required fields: previousKey
```

So the demo **simulates** PingFederate's attestor with a separate Ed25519 key in `.keys/attestation.env`, signing with biscuit-auth. The flow, the policy and the trust model are exactly what PingFederate would do. Only the signer is a stand-in.

There are three ways to get the real thing:

1. **biscuit-java catches up** with the newer third-party format. Then the attestor can be a small PingFederate endpoint or plugin.
2. **A sidecar attestor** next to PingFederate, using biscuit-auth. PingFederate decides that MFA happened; the sidecar signs.
3. **Step up at the IdP and re-exchange.** This works today, and it's the most "hybrid" option. Run MFA in PingFederate and put the `amr` claim in the JWT. Then make another token exchange and map `amr` into the authority block. The generator already allows an `amr` fact; it's in the default fact list. The cost is a round trip to PingFederate for step-up, which you'd make anyway for the MFA itself. The demo doesn't wire this up, because its HTML form login has no MFA, but nothing in the plugin stops it.

## 3. Attenuation: narrowing without asking

With the write unlocked, the demo app's **Attenuate** buttons append blocks that only ever narrow the token:

| Button | Block appended | Effect |
|---|---|---|
| Read-only | `check if operation("read");` | POST → `403`, naming the failed check |
| Only this order | `check if resource($r), $r == "/orders/999";` | `/orders/999` → 200, `/orders/123` → 403 |
| Expire in 60 s | `check if time($t), $t <= <now+60s>;` | Valid for a minute, even though PingFederate gave it five |
| Custom | your Datalog | e.g. `check if operation("read");` |

None of these call PingFederate, and none need a key. This is the Trust Lab's delegation step, now on a token that started life in an enterprise IdP. A gateway can hand a downstream service a token that's read-only, for one order, for one minute, in microseconds.

Two properties are worth checking yourself in the app:

- **Values can't inject Datalog.** The order ID and the time go into the block as parameters, not pasted text. Even so, the app only accepts order IDs of letters, digits, `-` and `_`.
- **A holder can't widen a token.** Append a block that says `amr("mfa"); scope("orders:admin");` yourself and POST: still `403`. Facts in an ordinary appended block aren't trusted by the policy. Only the authority block and the attestation key are.

**Seal** finishes the token: no further blocks can be appended, and the app disables those buttons. **Fresh Biscuit from PingFederate** runs the exchange again.

## 4. Revocation and certificate binding

The [standalone demo](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens/blob/main/scripts/demo.sh) (`make demo`, 19 checks, no PingFederate needed) covers two things the web app doesn't:

- **Revocation.** Each block has a revocation ID. Revoke the **authority block's** ID, which the plugin logs at mint time, and the original token *and every narrowed copy* fail. A token with a different ID is unaffected.
- **Certificate binding.** A token minted with a `cnf_x5t_s256` attribute only works when presented over the matching client certificate.

## What is not proven

The prototype works end to end. That's different from being production-ready:

- **PingFederate as the MFA attestor**: blocked by the biscuit-java format gap above; the demo simulates it.
- **Revocation distribution**: orders-api reads revoked IDs from a file. Getting them to every service quickly, by push, pull or short lifetimes, is a design problem I haven't solved here.
- **Introspection**: PingFederate can confirm a narrowed Biscuit's signature, but not whether it's *authorized*. That depends on request facts only the service has. `active: true` would mean "authentic and unexpired", nothing more.
- **Policy governance**: each service carries its own Datalog. Keeping policies consistent across services needs version control, review and tests, like any other code.
- **Ecosystem**: PingAccess and off-the-shelf gateways don't understand Biscuits. The hybrid sidesteps this by keeping JWTs at the edge, but it's a real limit on how far in the Biscuit can go.
- **Demo shortcuts**: HS256 JWTs with a symmetric key, generated secrets in local Terraform state, self-signed TLS, and the root key in a PingFederate config field rather than an HSM.
- **Size**: every block adds bytes. The demo's token grew from 436 bytes (one block) to about 1 KB (four blocks). Seal early if headers matter.

## Back to the Trust Lab's list

Part 4 of the Trust Lab ended with what a production version would need. Here's where an IdP-minted root moves the needle, and where it doesn't:

| Trust Lab production need | With PingFederate minting the root |
|---|---|
| Persistent keys with rotation | **Better.** The key lives in the IdP's encrypted config; `root_key_id` supports rotation |
| Revocation | **Partly.** IDs are logged at mint and revoking the authority block cascades; distribution is still open |
| Authenticated transports | **Better.** Certificate binding via `cnf_x5t_s256` |
| Payer consent | **Possible.** PingFederate's consent and authorization policies run before the exchange |
| Durable accounting, reconciliation | Unchanged; that's the clearinghouse's job, not the IdP's |

## Wrapping up

The thing I set out to test was whether an existing enterprise IdP could be the root of trust for Biscuits without giving up anything that makes either side useful. I think the answer is yes:

- PingFederate keeps login, MFA, consent and client governance.
- The edge keeps speaking OAuth.
- One token exchange turns an access token into a capability that services can narrow, delegate and check offline.

Try to break it. Clone the [repo](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens), run `make up tf-plan tf-apply web`, and see if you can make orders-api accept a write it shouldn't. If you work on PingFederate or Biscuit, I'd especially like feedback on the fact vocabulary, the reserved names, and the step-up options. Open an issue on GitHub.

Thanks for reading the series.
