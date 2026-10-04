---
title: Building a PingFederate token generator that mints Biscuits
published: false
description: >-
  A PingFederate SDK TokenGenerator that turns token exchange attributes into a
  signed Biscuit authority block: no Datalog injection, no forged request facts,
  and the output detail I only found by disassembling PingFederate.
tags: 'pingfederate, java, security, oauth'
series: Biscuit meets PingFederate
cover_image: null
canonical_url: null
devto: true
devto_id: 4795596
---

*Repo: [darkedges/pf12.3-biscuit-datalog-tokens](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens), plugin source in [`pf-biscuit-generator/`](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens/tree/main/pf-biscuit-generator)*

Part 1 argued for a hybrid: PingFederate issues JWTs at the edge, and token exchange turns them into Biscuits for everything inside. This part builds the one piece PingFederate doesn't ship, a **token generator** that mints a Biscuit.

It's a few hundred lines of Java. Most of the interesting decisions aren't in the Java, though. They're about what you let into the authority block.

## 1. The SDK contract

PingFederate's token exchange calls token generators through the same SDK interface its WS-Trust STS uses, `org.sourceid.wstrust.plugin.generate.TokenGenerator`. A generator does three things:

- **describes itself**: its name, admin UI fields, the token type it produces, and its attribute contract;
- **receives configuration** when an admin saves the instance;
- **generates a token** from a map of attributes.

The descriptor is where the token type lives. That URN is what clients send as `requested_token_type`:

```java
public static final String TOKEN_TYPE = "urn:darkedges:params:oauth:token-type:biscuit";

descriptor = new TokenPluginDescriptor(NAME, this, gui, TOKEN_TYPE, Set.of("subject"));
descriptor.setSupportsExtendedContract(true);
```

The core contract is just `subject`. The extended contract lets an admin add `client_id`, `scope`, `group`, `amr` or anything else the processor policy provides, without changing code.

The admin UI exposes six fields:

| Field | Becomes |
|---|---|
| Root Private Key | The Ed25519 key that signs the authority block (an encrypted field) |
| Root Key ID | `root_key_id` in the token, for key rotation |
| Issuer | `issuer("…")` |
| Token Lifetime (seconds) | `check if time($t), $t <= <now + lifetime>` |
| Audiences | `check if audience($a), {…}.contains($a)` |
| Fact Attributes | Which contract attributes become facts |

The plugin uses [biscuit-java](https://github.com/biscuit-auth/biscuit-java) 4.0.1, the JVM implementation of Biscuit.

## 2. Attributes in, facts out, and never as strings

This is the first design rule, and it's easy to get wrong. The tempting implementation is string building:

```java
// DON'T
token.add_authority_fact("user(\"" + subject + "\")");
```

If a subject ever contains `alice"); scope("orders:admin`, you've just let an attribute value write Datalog. In an IdP, attribute values come from directories, upstream federation partners and user-editable profiles. They aren't safe input.

So every value goes through biscuit-java's builder API as a **string term**. A term is data and is never parsed as Datalog:

```java
token.set_context("pingfederate:token-exchange");
token.add_authority_fact(fact("issuer", List.of(string(issuer))));

for (Map.Entry<String, String> e : factAttributes.entrySet())
{
    for (String value : values(attributes, e.getKey()))
    {
        token.add_authority_fact(fact(e.getValue(), List.of(string(value))));
    }
}
```

The checks are built the same way: predicates, variables and expressions, not strings. Here's the expiry:

```java
// check if time($t), $t <= <expiresAt>
token.add_authority_check(check(
        pred("time", List.of(var("t"))),
        new Expression.Binary(Expression.Op.LessOrEqual,
                new Expression.Value(var("t")),
                new Expression.Value(date(Date.from(expiresAt))))));
```

There's a unit test that mints a token for the subject `mallory"); scope("orders:write`. It checks that the result contains exactly one scope fact and that a write is still refused.

A small but useful detail: OAuth's `scope` arrives as one space-separated string. The minter splits it into one `scope("…")` fact per scope, so Datalog policies can match individual scopes.

## 3. The fact names a minter must refuse

The second design rule is subtler, and I think it's the most important thing in this article.

A Biscuit authorizer combines facts from two places:

- **the token**, whose authority block is trusted;
- **the service itself**, which adds *ambient* facts describing the request it's handling: `time(...)`, `operation("read")`, `resource("/orders/123")`, `audience("orders-api")`.

Then it runs a policy like:

```datalog
allow if scope("orders:read"), operation("read");
allow if scope("orders:write"), operation("write"), amr("mfa") trusting authority, ed25519/<attestation key>;
deny if true;
```

By default, the authorizer trusts authority-block facts **exactly as much as its own**. So if any PingFederate attribute were ever mapped to a fact called `operation`, a token could carry `operation("write")` and satisfy the write rule *on a read request*. The token would be forging facts about the request.

So the minter has a reserved list, and refuses to start if an admin maps an attribute onto any of these names:

```java
public static final Set<String> RESERVED_FACTS = Set.of(
        "time", "operation", "resource", "audience", "tls_client_cert_sha256", "issuer", "hop");
```

`issuer` is on the list because the plugin sets it from configuration. `hop` is reserved for services to tag delegation hops.

The broader lesson: **the fact vocabulary is a contract between your IdP and every service that verifies its tokens.** Which names the IdP asserts (`user`, `client`, `scope`, `group`, `amr`) and which names services assert (`time`, `operation`, `resource`) must never overlap. Write it down and version it.

## 4. Checks that bind the token

Beyond expiry and audience, the minter supports one more check: **certificate binding**, the Biscuit equivalent of [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)'s `cnf.x5t#S256`. If the processor policy supplies a `cnf_x5t_s256` attribute, the authority block gets:

```datalog
check if tls_client_cert_sha256($c), $c == "<thumbprint>";
```

The service adds `tls_client_cert_sha256(...)` from its mTLS handshake. A stolen token presented over a different client certificate fails the check. The [standalone demo](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens/blob/main/scripts/demo.sh) covers all three cases: no certificate, the wrong certificate, and the right one.

## 5. Getting the output right: what I disassembled

A generator returns a `SecurityToken`. For anything that isn't SAML, that means a `BinarySecurityToken`, an XML-era type with "encoded data" and an encoding type. The SDK doesn't document what the OAuth token exchange endpoint does with it. Would PingFederate base64 the data again? Decode it? Wrap it?

So I disassembled the class that builds the token exchange response in PingFederate 12.3.3, `TokenGeneratorOutputGenerationStrategy`, with `javap -c`. It does three things:

- returns `BinarySecurityToken.getEncodedData()` **verbatim** as `access_token`;
- sets `token_type` to `N_A`;
- computes `expires_in` from `getExpiryDate()` if one is set.

That's good news: the Biscuit's native base64url serialization passes through untouched, and verifiers can read it directly. The generator sets the encoding type and the expiry date so `expires_in` is correct:

```java
BinarySecurityToken bst = new BinarySecurityToken(XmlIDUtil.createID(), TOKEN_TYPE);
bst.setEncodingType(BinarySecurityToken.BASE64_URL_ENCODING_TYPE);
bst.setEncodedData(minted.token());
bst.setCreatedDate(new Date());
bst.setExpiryDate(Date.from(minted.expiresAt()));
return bst;
```

The same mint also logs the authority block's **revocation ID** along with the subject. Revoking that ID revokes the token *and every narrowed copy made from it*, because each appended block chains from the authority block. Logging it at mint time is what makes revocation possible later.

## 6. Keys and rotation

The root key is Ed25519, stored in an **encrypted** configuration field, so PingFederate replicates it across a cluster like any other secret. The plugin's jar is also a CLI, so you can generate the key with the same code that uses it:

```bash
java -jar pf.plugins.biscuit-token-generator.jar keygen
# private=49309A02…
# public=ed25519/0155b736…
```

The **Root Key ID** goes into each token. Verifiers look up the public key by that ID, which is how you rotate: publish the new public key, switch the generator to the new key ID, then retire the old key once no unexpired tokens use it.

One biscuit-java detail cost me a test run: `Biscuit.from_b64url(token, publicKey)` **drops** `root_key_id`. The overload that takes a `KeyDelegate` receives the ID, which is the one you want for rotation anyway.

## 7. Packaging: shading, and building against the image

Two practical problems:

**Classpath clashes.** PingFederate ships its own vavr (0.10.2) and protobuf, and biscuit-java needs slightly different versions. The plugin is a shaded jar with every dependency relocated under `com.darkedges.pingfederate.biscuit.shaded.*`, so it can't collide with the server's classpath.

**Where the SDK comes from.** The SDK jars aren't on Maven Central, so the [Dockerfile](https://github.com/darkedges/pf12.3-biscuit-datalog-tokens/blob/main/docker/pingfederate/Dockerfile) takes them **from the PingFederate image itself**. A build stage copies `/opt/server/server/default/lib` out of `pingidentity/pingfederate:2511-12.3.3`, compiles and tests the plugin on JDK 11, and the final stage copies the jar into `deploy/`. The plugin always compiles against exactly the version it runs on.

There's one runtime gotcha with the Ping Docker images. The server runs from `/opt/out/instance`, and the startup hooks copy `/opt/server` into it **only on a fresh volume**. Rebuild the image while the volume persists and you're still running the old jar. The repo's `make redeploy` wipes the volume for that reason.

## 8. Tests and an interop check

The plugin has two test classes:

- `BiscuitMinterTest`: authority facts, expiry, wrong audience, wrong key, attenuation, injection, the reserved-name refusal, and certificate binding.
- `BiscuitTokenGeneratorTest`: drives the plugin through PingFederate's own SDK types, `Configuration`, `TokenContext`, `AttributeValue` and `BinarySecurityToken`, and verifies the output.

Two findings from writing them:

- **biscuit-java's default authorizer budget is 5 ms.** A cold JVM blows through that on the first evaluation and throws a `Timeout`. Pass `RunLimits` explicitly.
- **The SDK test needs PingFederate internals.** `XmlIDUtil.createID()` starts PingFederate's internal registry, which uses reflection that JDK 17+ blocks without `--add-opens`. I run the tests on JDK 11, as the Docker build does.

The interop check matters most: **tokens minted by biscuit-java in PingFederate verify in biscuit-auth 6 (Rust)** using only the public key. That's what Part 3's resource server uses.

## Next

The plugin is half the story. In Part 3 we configure PingFederate around it with Terraform: the login, the JWT token manager, the processor policy and the generator mapping. Two resources need the generic `restapi` provider, because the PingFederate provider has no resource for token generators. Then we test it end to end in a browser.
