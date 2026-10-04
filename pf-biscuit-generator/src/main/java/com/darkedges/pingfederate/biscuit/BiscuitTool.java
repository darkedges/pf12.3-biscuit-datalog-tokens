package com.darkedges.pingfederate.biscuit;

import static org.biscuitsec.biscuit.token.builder.Utils.fact;
import static org.biscuitsec.biscuit.token.builder.Utils.string;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.token.ThirdPartyBlockContents;
import org.biscuitsec.biscuit.token.ThirdPartyBlockRequest;
import org.biscuitsec.biscuit.token.builder.Block;

/**
 * Command line companion to the plugin, packaged in the same jar.
 *
 * <pre>
 * keygen                                   generate an Ed25519 root (or attestation) key
 * mint   --key HEX --issuer URL [--aud a,b] [--lifetime SEC] [--facts subject,scope,...] name=value ...
 *                                          mint exactly as the PingFederate generator would
 * attest --key HEX --request B64URL fact=value ...
 *                                          sign a third-party block (PingFederate as attestor)
 * </pre>
 */
public final class BiscuitTool
{
    private BiscuitTool()
    {
    }

    public static void main(String[] args) throws Exception
    {
        if (args.length == 0)
        {
            usage();
            return;
        }
        List<String> rest = new ArrayList<>(Arrays.asList(args).subList(1, args.length));
        switch (args[0])
        {
            case "keygen":
                KeyPair kp = new KeyPair();
                System.out.println("private=" + kp.toHex());
                System.out.println("public=ed25519/" + kp.public_key().toHex().toLowerCase());
                break;
            case "mint":
                mint(rest);
                break;
            case "attest":
                attest(rest);
                break;
            default:
                usage();
                System.exit(2);
        }
    }

    private static void mint(List<String> args) throws Exception
    {
        Map<String, String> opts = options(args);
        BiscuitMinter.Builder b = BiscuitMinter.builder()
                .rootKey(new KeyPair(require(opts, "key")))
                .issuer(require(opts, "issuer"))
                .lifetime(Duration.ofSeconds(Long.parseLong(opts.getOrDefault("lifetime", "300"))));
        if (opts.containsKey("aud"))
        {
            b.audiences(Arrays.asList(opts.get("aud").split(",")));
        }
        if (opts.containsKey("facts"))
        {
            b.factAttributes(Arrays.asList(opts.get("facts").split(",")));
        }

        Map<String, List<String>> attributes = new LinkedHashMap<>();
        for (String a : args)
        {
            int eq = a.indexOf('=');
            attributes.computeIfAbsent(a.substring(0, eq), k -> new ArrayList<>()).add(a.substring(eq + 1));
        }

        BiscuitMinter.Minted minted = b.build().mint(attributes);
        System.err.println(minted.datalog());
        System.err.println("revocation_ids=" + minted.revocationIds());
        System.out.println(minted.token());
    }

    private static void attest(List<String> args) throws Exception
    {
        Map<String, String> opts = options(args);
        KeyPair key = new KeyPair(require(opts, "key"));
        ThirdPartyBlockRequest request = ThirdPartyBlockRequest.fromBytes(
                Base64.getUrlDecoder().decode(require(opts, "request")));

        Block block = new Block();
        for (String a : args)
        {
            int eq = a.indexOf('=');
            block.add_fact(fact(a.substring(0, eq), List.of(string(a.substring(eq + 1)))));
        }

        ThirdPartyBlockContents contents = request.createBlock(key, block)
                .getOrElseThrow(e -> new IllegalStateException(e.toString()));
        System.out.println(Base64.getUrlEncoder().withoutPadding()
                .encodeToString(contents.serialize().toByteArray()));
    }

    /** Pulls --name value pairs out of args, leaving positional name=value arguments behind. */
    private static Map<String, String> options(List<String> args)
    {
        Map<String, String> opts = new LinkedHashMap<>();
        for (int i = 0; i < args.size(); )
        {
            if (args.get(i).startsWith("--") && i + 1 < args.size())
            {
                opts.put(args.get(i).substring(2), args.get(i + 1));
                args.remove(i);
                args.remove(i);
            }
            else
            {
                i++;
            }
        }
        return opts;
    }

    private static String require(Map<String, String> opts, String name)
    {
        String v = opts.get(name);
        if (v == null)
        {
            throw new IllegalArgumentException("--" + name + " is required");
        }
        return v;
    }

    private static void usage()
    {
        System.err.println("usage: keygen | mint --key HEX --issuer URL [--aud a,b] [--lifetime SEC] [--facts a,b] name=value... "
                + "| attest --key HEX --request B64URL fact=value...");
    }
}
