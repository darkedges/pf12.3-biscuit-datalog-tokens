package com.darkedges.pingfederate.biscuit;

import static org.biscuitsec.biscuit.token.builder.Utils.constrained_rule;
import static org.biscuitsec.biscuit.token.builder.Utils.date;
import static org.biscuitsec.biscuit.token.builder.Utils.fact;
import static org.biscuitsec.biscuit.token.builder.Utils.pred;
import static org.biscuitsec.biscuit.token.builder.Utils.set;
import static org.biscuitsec.biscuit.token.builder.Utils.string;
import static org.biscuitsec.biscuit.token.builder.Utils.var;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.Check.Kind;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.RevocationIdentifier;
import org.biscuitsec.biscuit.token.builder.Check;
import org.biscuitsec.biscuit.token.builder.Expression;
import org.biscuitsec.biscuit.token.builder.Term;

import io.vavr.control.Option;

/**
 * Turns a flat attribute map (what PingFederate hands a token generator) into a Biscuit authority block.
 *
 * <p>Independent of the PingFederate SDK so it can be unit tested and reused by the CLI.
 *
 * <p>Security rules this class enforces:
 * <ul>
 *   <li>Attribute values only ever become Datalog <em>string terms</em> via the builder API, never
 *       concatenated into Datalog source, so a value like {@code x"); right("admin} cannot inject facts.</li>
 *   <li>Only allow-listed attributes become facts, and the resulting fact names must not collide with
 *       {@link #RESERVED_FACTS ambient facts} the verifying service supplies. Authority facts are trusted
 *       exactly like authorizer facts, so a token carrying {@code operation("write")} would otherwise
 *       satisfy {@code allow if operation("write")} on a read request.</li>
 * </ul>
 */
public final class BiscuitMinter
{
    /** Fact names supplied by verifiers (ambient request context) or controlled by this minter. */
    public static final Set<String> RESERVED_FACTS = Set.of(
            "time", "operation", "resource", "audience", "tls_client_cert_sha256", "issuer", "hop");

    /** PingFederate attribute names that map to a different fact name. */
    public static final Map<String, String> DEFAULT_RENAMES = Map.of(
            "subject", "user",
            "client_id", "client");

    public static final String ATTR_CNF_X5T_S256 = "cnf_x5t_s256";

    private static final Pattern FACT_NAME = Pattern.compile("[a-z][a-z0-9_]{0,63}");

    private final KeyPair rootKey;
    private final Option<Integer> rootKeyId;
    private final String issuer;
    private final Duration lifetime;
    private final Set<String> audiences;
    private final Map<String, String> factAttributes;
    private final Clock clock;
    private final SecureRandom rng = new SecureRandom();

    private BiscuitMinter(Builder b)
    {
        this.rootKey = Objects.requireNonNull(b.rootKey, "rootKey");
        this.rootKeyId = Option.of(b.rootKeyId);
        this.issuer = Objects.requireNonNull(b.issuer, "issuer");
        this.lifetime = Objects.requireNonNull(b.lifetime, "lifetime");
        this.audiences = Collections.unmodifiableSet(new HashSet<>(b.audiences));
        this.clock = Objects.requireNonNull(b.clock, "clock");

        Map<String, String> mapping = new LinkedHashMap<>();
        for (String attr : b.factAttributes)
        {
            String factName = DEFAULT_RENAMES.getOrDefault(attr, attr);
            if (!FACT_NAME.matcher(factName).matches())
            {
                throw new IllegalArgumentException("Attribute '" + attr + "' is not a valid Datalog fact name");
            }
            if (RESERVED_FACTS.contains(factName))
            {
                throw new IllegalArgumentException(
                        "Attribute '" + attr + "' maps to reserved fact '" + factName + "' (supplied by verifiers)");
            }
            mapping.put(attr, factName);
        }
        this.factAttributes = Collections.unmodifiableMap(mapping);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public Minted mint(Map<String, ? extends Collection<String>> attributes) throws Error
    {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(lifetime);

        org.biscuitsec.biscuit.token.builder.Biscuit token = Biscuit.builder(rng, rootKey, rootKeyId);
        token.set_context("pingfederate:token-exchange");
        token.add_authority_fact(fact("issuer", List.of(string(issuer))));

        for (Map.Entry<String, String> e : factAttributes.entrySet())
        {
            for (String value : values(attributes, e.getKey()))
            {
                token.add_authority_fact(fact(e.getValue(), List.of(string(value))));
            }
        }

        // check if time($t), $t <= <expiresAt>
        token.add_authority_check(check(
                pred("time", List.of(var("t"))),
                new Expression.Binary(Expression.Op.LessOrEqual,
                        new Expression.Value(var("t")),
                        new Expression.Value(date(Date.from(expiresAt))))));

        // check if audience($a), {"a","b"}.contains($a)
        if (!audiences.isEmpty())
        {
            HashSet<Term> set = audiences.stream().map(a -> string(a)).collect(Collectors.toCollection(HashSet::new));
            token.add_authority_check(check(
                    pred("audience", List.of(var("a"))),
                    new Expression.Binary(Expression.Op.Contains,
                            new Expression.Value(set(set)),
                            new Expression.Value(var("a")))));
        }

        // Sender constraint, the Biscuit equivalent of RFC 8705 cnf.x5t#S256:
        // check if tls_client_cert_sha256($c), $c == "<thumbprint>"
        List<String> thumbprints = values(attributes, ATTR_CNF_X5T_S256);
        if (!thumbprints.isEmpty())
        {
            token.add_authority_check(check(
                    pred("tls_client_cert_sha256", List.of(var("c"))),
                    new Expression.Binary(Expression.Op.Equal,
                            new Expression.Value(var("c")),
                            new Expression.Value(string(thumbprints.get(0))))));
        }

        Biscuit biscuit = token.build();
        List<String> revocationIds = biscuit.revocation_identifiers().stream()
                .map(RevocationIdentifier::toHex)
                .collect(Collectors.toList());
        return new Minted(biscuit.serialize_b64url(), expiresAt, revocationIds, biscuit.print());
    }

    private static Check check(org.biscuitsec.biscuit.token.builder.Predicate body, Expression expression)
    {
        return new Check(Kind.One, constrained_rule("query", List.of(), List.of(body), List.of(expression)));
    }

    private static List<String> values(Map<String, ? extends Collection<String>> attributes, String name)
    {
        Collection<String> raw = attributes.get(name);
        if (raw == null)
        {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String v : raw)
        {
            if (v == null)
            {
                continue;
            }
            // OAuth scope arrives as one space-delimited string; emit one fact per scope.
            if ("scope".equals(name))
            {
                for (String s : v.trim().split("\\s+"))
                {
                    if (!s.isEmpty())
                    {
                        out.add(s);
                    }
                }
            }
            else
            {
                out.add(v);
            }
        }
        return out;
    }

    /** Result of a mint: the wire token plus what an operator needs to revoke or audit it. */
    public static final class Minted
    {
        private final String token;
        private final Instant expiresAt;
        private final List<String> revocationIds;
        private final String datalog;

        Minted(String token, Instant expiresAt, List<String> revocationIds, String datalog)
        {
            this.token = token;
            this.expiresAt = expiresAt;
            this.revocationIds = List.copyOf(revocationIds);
            this.datalog = datalog;
        }

        /** Base64url-encoded Biscuit, the canonical wire format. */
        public String token() { return token; }

        public Instant expiresAt() { return expiresAt; }

        /** Hex revocation IDs; index 0 is the authority block, which revokes every attenuated descendant. */
        public List<String> revocationIds() { return revocationIds; }

        public String datalog() { return datalog; }
    }

    public static final class Builder
    {
        private KeyPair rootKey;
        private Integer rootKeyId;
        private String issuer;
        private Duration lifetime = Duration.ofMinutes(5);
        private Collection<String> audiences = List.of();
        private Collection<String> factAttributes = List.of("subject", "client_id", "scope", "group", "amr");
        private Clock clock = Clock.systemUTC();

        public Builder rootKey(KeyPair rootKey) { this.rootKey = rootKey; return this; }

        public Builder rootKeyId(Integer rootKeyId) { this.rootKeyId = rootKeyId; return this; }

        public Builder issuer(String issuer) { this.issuer = issuer; return this; }

        public Builder lifetime(Duration lifetime) { this.lifetime = lifetime; return this; }

        public Builder audiences(Collection<String> audiences) { this.audiences = audiences; return this; }

        public Builder factAttributes(Collection<String> factAttributes) { this.factAttributes = factAttributes; return this; }

        public Builder clock(Clock clock) { this.clock = clock; return this; }

        public BiscuitMinter build() { return new BiscuitMinter(this); }
    }
}
