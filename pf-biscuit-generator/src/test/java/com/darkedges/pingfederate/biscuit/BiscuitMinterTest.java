package com.darkedges.pingfederate.biscuit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Authorizer;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.Block;
import org.junit.jupiter.api.Test;

class BiscuitMinterTest
{
    private static final Instant NOW = Instant.parse("2026-10-04T11:00:00Z");

    // biscuit-java defaults to a 5 ms evaluation budget, which a cold JVM can exceed.
    private static final RunLimits LIMITS = new RunLimits(1000, 100, Duration.ofMillis(500));

    private final KeyPair root = new KeyPair();

    private BiscuitMinter minter()
    {
        return BiscuitMinter.builder()
                .rootKey(root)
                .issuer("https://sso.example.com")
                .lifetime(Duration.ofMinutes(5))
                .audiences(List.of("orders-api", "billing-api"))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();
    }

    private static final Map<String, List<String>> ALICE = Map.of(
            "subject", List.of("alice"),
            "client_id", List.of("orders-web"),
            "scope", List.of("orders:read orders:write"));

    /** Mirrors a resource server: ambient request facts plus local policy. */
    private Authorizer authorizer(Biscuit token, String audience, String operation, Instant at) throws Exception
    {
        Authorizer a = token.authorizer();
        a.add_fact("time(" + at + ")");
        a.add_fact("audience(\"" + audience + "\")");
        a.add_fact("operation(\"" + operation + "\")");
        a.add_fact("resource(\"/orders/123\")");
        a.add_policy("allow if scope(\"orders:read\"), operation(\"read\")");
        a.add_policy("allow if scope(\"orders:write\"), operation(\"write\")");
        a.add_policy("deny if true");
        return a;
    }

    private Biscuit verify(String token) throws Exception
    {
        return Biscuit.from_b64url(token, root.public_key());
    }

    @Test
    void mintsAuthorityFactsAndAuthorizes() throws Exception
    {
        BiscuitMinter.Minted minted = minter().mint(ALICE);
        Biscuit token = verify(minted.token());

        assertTrue(minted.datalog().contains("user(\"alice\")"), minted.datalog());
        assertTrue(minted.datalog().contains("client(\"orders-web\")"), minted.datalog());
        assertTrue(minted.datalog().contains("scope(\"orders:write\")"), minted.datalog());
        assertEquals(NOW.plus(Duration.ofMinutes(5)), minted.expiresAt());
        assertEquals(1, minted.revocationIds().size());

        authorizer(token, "orders-api", "write", NOW.plusSeconds(60)).authorize(LIMITS);
    }

    @Test
    void rejectsExpiredToken() throws Exception
    {
        Biscuit token = verify(minter().mint(ALICE).token());
        assertThrows(Error.FailedLogic.class,
                () -> authorizer(token, "orders-api", "read", NOW.plus(Duration.ofMinutes(6))).authorize(LIMITS));
    }

    @Test
    void rejectsWrongAudience() throws Exception
    {
        Biscuit token = verify(minter().mint(ALICE).token());
        assertThrows(Error.FailedLogic.class,
                () -> authorizer(token, "hr-api", "read", NOW).authorize(LIMITS));
    }

    @Test
    void rejectsTokenFromAnotherRootKey() throws Exception
    {
        String token = minter().mint(ALICE).token();
        assertThrows(Error.class, () -> Biscuit.from_b64url(token, new KeyPair().public_key()));
    }

    @Test
    void attenuationNarrowsWithoutPingFederate() throws Exception
    {
        Biscuit token = verify(minter().mint(ALICE).token());

        // A gateway restricts the token to read-only before passing it downstream.
        Block block = token.create_block();
        block.add_check("check if operation(\"read\")");
        Biscuit attenuated = verify(token.attenuate(block).serialize_b64url());

        authorizer(attenuated, "orders-api", "read", NOW).authorize(LIMITS);
        assertThrows(Error.FailedLogic.class,
                () -> authorizer(attenuated, "orders-api", "write", NOW).authorize(LIMITS));
        assertEquals(2, attenuated.revocation_identifiers().size());
    }

    @Test
    void attributeValuesCannotInjectDatalog() throws Exception
    {
        Map<String, List<String>> evil = Map.of(
                "subject", List.of("mallory\"); scope(\"orders:write"),
                "scope", List.of("orders:read"));
        BiscuitMinter.Minted minted = minter().mint(evil);
        Biscuit token = verify(minted.token());

        assertThrows(Error.FailedLogic.class,
                () -> authorizer(token, "orders-api", "write", NOW).authorize(LIMITS));
        assertEquals(1, token.authorizer().query("data($s) <- scope($s)").size());
    }

    @Test
    void refusesToMapAttributesOntoAmbientFacts()
    {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> BiscuitMinter.builder()
                .rootKey(root).issuer("x").factAttributes(List.of("subject", "operation")).build());
        assertTrue(e.getMessage().contains("reserved"), e.getMessage());
    }

    @Test
    void senderConstrainedTokenNeedsMatchingClientCert() throws Exception
    {
        Map<String, List<String>> bound = new java.util.HashMap<>(ALICE);
        bound.put(BiscuitMinter.ATTR_CNF_X5T_S256, List.of("abc123"));
        Biscuit token = verify(minter().mint(bound).token());

        Authorizer ok = authorizer(token, "orders-api", "read", NOW);
        ok.add_fact("tls_client_cert_sha256(\"abc123\")");
        ok.authorize(LIMITS);

        Authorizer stolen = authorizer(token, "orders-api", "read", NOW);
        stolen.add_fact("tls_client_cert_sha256(\"other\")");
        assertThrows(Error.FailedLogic.class, () -> stolen.authorize(LIMITS));
    }
}
