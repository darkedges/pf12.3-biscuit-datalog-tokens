---
title: 'Who mints the first Biscuit? PingFederate, token exchange and a hybrid model'
published: false
description: >-
  Your IdP already knows who Alice is. Here's how PingFederate can mint the root
  Biscuit through OAuth token exchange, and why JWTs at the edge plus Biscuits
  inside is a hybrid that works.
tags: 'pingfederate, oauth, security, authorization'
series: Biscuit meets PingFederate
cover_image: null
canonical_url: null
devto: true
devto_id: 4795595
---

*Repo: [darkedges/pf12.3-biscuit-datalog-tokens](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens)*

In the [Biscuit Trust Lab](https://dev.to/darkedges/delegating-authority-across-companies-with-biscuit-tokens-5583) series, Alice asked PlannerCo to do some work. PlannerCo split it between ResearchCo and ComputeCo, ResearchCo passed part of it to SearchCo, and every hop narrowed the token it was handed. Nobody called home to ask permission, and nobody could widen what they'd been given.

There was one thing that series never answered: **where did Alice's first token come from?** In the lab, the platform minted it. In a real company, Alice doesn't exist until an identity provider says she does. She logs in with a password and probably MFA, against a directory the security team runs, through an IdP that every application already trusts.

This series is about closing that gap with PingFederate. Over four parts:

1. **Who mints the first Biscuit?** Why a hybrid of JWTs and Biscuits works, and how OAuth token exchange joins them (this article).
2. **Building a PingFederate token generator that mints Biscuits**: the SDK plugin, the Datalog design rules, and what I had to disassemble to get the output right.
3. **Configuring the exchange with Terraform and testing it end to end**: 17 resources, two of which the provider can't manage, and a demo app that shows every request and response.
4. **Step-up MFA, attenuation, and what's honestly not done**, including a library gap that stops PingFederate from being the MFA attestor today.

## Two token models, two strengths

If you've read the Trust Lab, you know what Biscuits are good at. If you've run an IdP, you know what JWTs are good at. The problem is that they're good at different things:

| | JWT access token from your IdP | Biscuit |
|---|---|---|
| Who can narrow it | Only the issuer, by minting a new one | Anyone holding it, offline, by appending a block |
| Can a holder widen it? | No (it's signed) | No (appended blocks can only add checks) |
| Authorization logic | Claims, interpreted by each service's code | Datalog policy, evaluated with the token's facts |
| Delegation across hops | Token exchange back at the IdP for each hop | Append and pass on |
| Who understands it | Everything: gateways, PingAccess, API managers, every OAuth library | Biscuit libraries only |
| Login, MFA, consent, client registration | Built into the IdP | Not its job |

Neither column wins. JWTs are what the outside world speaks: browsers, mobile apps, API gateways, and the edge of your network all expect OAuth. Biscuits are better once the token is inside, moving between services or companies that need to narrow it as it goes.

## The hybrid: JWTs at the edge, Biscuits inside

So don't choose. Let each format do what it's good at, and put a well-defined seam between them:

```
                north-south: standard OAuth                       east-west: capabilities
 Browser ──login──▶ PingFederate ──JWT──▶ client / gateway ──Biscuit──▶ service A ──narrowed Biscuit──▶ service B
                         ▲                     │
                         └── token exchange ───┘
                             (JWT in, Biscuit out)
```

The seam is **OAuth 2.0 Token Exchange, [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)**. The client presents the JWT it already has as the `subject_token` and asks for a different kind of token back:

```bash
curl -k -X POST 'https://localhost:9031/as/token.oauth2' \
  -u "orders-web:$CLIENT_SECRET" \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$JWT" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'requested_token_type=urn:darkedges:params:oauth:token-type:biscuit'
```

And PingFederate answers:

```json
{
  "access_token": "CAESiwMKoAIKBmlzc3VlcgoWaHR0cHM6Ly9sb2NhbGhvc3Q6OTAzMQoFYWxp…",
  "issued_token_type": "urn:darkedges:params:oauth:token-type:biscuit",
  "token_type": "N_A",
  "expires_in": 299
}
```

That `access_token` is a Biscuit, signed with an Ed25519 key that PingFederate holds. `token_type: N_A` is RFC 8693's way of saying "this isn't an OAuth access token in the usual sense". The requested token type is a URN I made up. RFC 8693 lets you define your own, and PingFederate routes on it.

Here's what's inside, its **authority block**:

```datalog
issuer("https://localhost:9031");
user("alice");
client("orders-web");
scope("orders:read");
scope("orders:write");
check if time($t), $t <= 2026-10-04T11:23:13Z;
check if audience($a), {"orders-api"}.contains($a);
```

Everything in it came from PingFederate: the user it authenticated, the client it registered, the scopes it granted, the lifetime and audience policy it enforces. From here on, the Trust Lab mechanics apply unchanged: append a block, narrow it, pass it on.

## Why this works as a hybrid

It's tempting to see token exchange as a workaround. I think it's the right design, for five reasons.

**1. PingFederate stays the authority.** Login, MFA, account lockout, consent, client registration, scope policy and auditing all stay where they are. The Biscuit doesn't replace any of it. It carries the *result* of it, signed by the same IdP that produced it.

**2. Nothing at the edge has to change.** Browsers, mobile apps, PingAccess and your API gateway keep speaking standard OAuth. Only the components that want offline narrowing ever see a Biscuit.

**3. PingFederate decides what goes into the root token.** Token exchange runs through a *processor policy* in PingFederate. It validates the incoming JWT, picks the attributes it trusts (subject, client, scope), and can refuse to issue at all. That's the hook for central governance: the set of facts in the authority block is controlled in one place, not by whoever builds a client.

**4. Below the seam, delegation stops costing a round trip.** With JWTs only, each hop that wants a narrower token has to go back to the IdP and exchange again. With a Biscuit, the hop appends `check if operation("read")` and moves on. PingFederate is consulted once, at the seam.

**5. It answers the Trust Lab's production list.** Part 4 of the Trust Lab ended with what a production version would need, including *persistent keys with rotation* and *revocation*. An IdP already has key management. Here the Biscuit carries a `root_key_id` so verifiers can pick the right key during rotation, and every mint logs the authority block's revocation ID.

## Bridging back to the Trust Lab

Put Alice's company IdP in front of the Trust Lab scenario and the chain becomes:

1. Alice logs in to PingFederate at her company and gets a JWT, like any other OAuth app.
2. PlannerCo, a registered OAuth client, exchanges that JWT for a Biscuit. The authority block says `user("alice")`, `client("plannerco")`, and the scopes Alice's company allows.
3. PlannerCo attenuates and delegates to ResearchCo and ComputeCo, exactly as in [Part 2 of the Trust Lab](https://dev.to/darkedges/attenuating-biscuit-tokens-and-signing-the-delegation-chain-5a2f).
4. Each receiver checks the chain with PingFederate's **public key** and its own policy, like the [receiver's authorizer in Part 3](https://dev.to/darkedges/local-policy-shared-facts-the-receivers-datalog-authorizer-2beg). None of them needs to call PingFederate.

The hands-on parts of this series use a smaller example from the repository so you can run it: users `alice` and `bob`, a client called `orders-web`, and an `orders-api` that lets you read with `orders:read` but only write with `orders:write` *plus* an MFA attestation. The mechanics are the same.

## What's inside PingFederate

Token exchange in PingFederate is a small pipeline. It's worth seeing the parts before we build one of them:

```
subject_token (JWT)
   │
   ▼
Token processor ............ validates the JWT with the access token manager that issued it
   │
   ▼
Processor policy ........... picks subject, client_id, scope; can reject
   │
   ▼
Generator mapping .......... maps policy attributes onto the generator's contract
   │
   ▼
Token generator ............ ← this is the plugin: turns attributes into a Biscuit
   ▲
Generator group ............ routes requested_token_type=…:biscuit to the generator
```

Everything except the generator ships with PingFederate. The generator is a Java plugin written against the PingFederate SDK's `TokenGenerator` interface, and that's the subject of the next part.

## What this doesn't do

I'd rather say this up front:

- **PingFederate can mint the root token, but it can't yet sign the MFA attestation block.** The Java Biscuit library is a format version behind the Rust one for third-party blocks. Part 4 covers this and the workaround.
- **PingFederate can't introspect a narrowed Biscuit meaningfully.** It can check the signature, but whether a request is *authorized* depends on facts only the receiving service has.
- **Off-the-shelf gateways don't understand Biscuits.** That's why the hybrid keeps JWTs at the edge.

## Next

In Part 2 we build the token generator: the SDK interface, how attributes become Datalog facts without injection, which fact names a minter must refuse to issue, and the detail I only found by disassembling PingFederate's token exchange code.

If you want to jump ahead, the [README](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens#step-by-step-deploy-and-test) gets you from `git clone` to a PingFederate-minted Biscuit in about ten commands.
