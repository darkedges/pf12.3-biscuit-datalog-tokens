package com.darkedges.pingfederate.biscuit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.token.Biscuit;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.wstrust.model.BinarySecurityToken;
import org.sourceid.wstrust.plugin.generate.TokenContext;
import org.sourceid.wstrust.plugin.process.TokenPluginDescriptor;

/** Drives the plugin through the same SDK types PingFederate uses at runtime. */
class BiscuitTokenGeneratorTest
{
    @Test
    void generatesBiscuitFromTokenContext() throws Exception
    {
        KeyPair root = new KeyPair();
        Configuration config = new Configuration();
        config.addField(new Field(BiscuitTokenGenerator.FIELD_ROOT_KEY, root.toHex()));
        config.addField(new Field(BiscuitTokenGenerator.FIELD_ROOT_KEY_ID, "7"));
        config.addField(new Field(BiscuitTokenGenerator.FIELD_ISSUER, "https://sso.example.com"));
        config.addField(new Field(BiscuitTokenGenerator.FIELD_LIFETIME, "300"));
        config.addField(new Field(BiscuitTokenGenerator.FIELD_AUDIENCES, "orders-api"));
        config.addField(new Field(BiscuitTokenGenerator.FIELD_FACT_ATTRIBUTES, "subject,client_id,scope"));

        BiscuitTokenGenerator generator = new BiscuitTokenGenerator();
        generator.configure(config);

        TokenContext context = new TokenContext();
        context.setSubjectAttributes(Map.of(
                "subject", new AttributeValue("alice"),
                "client_id", new AttributeValue("orders-web"),
                "scope", new AttributeValue("orders:read")));

        BinarySecurityToken bst = generator.generateToken(context);
        assertEquals(BinarySecurityToken.BASE64_URL_ENCODING_TYPE, bst.getEncodingType());
        assertTrue(bst.getExpiryDate().after(new java.util.Date()));

        // Verifiers select the public key by root_key_id, which is how rotation works.
        java.util.List<Integer> requestedKeyIds = new java.util.ArrayList<>();
        Biscuit token = Biscuit.from_b64url(bst.getEncodedData(), keyId -> {
            requestedKeyIds.add(keyId.getOrNull());
            return io.vavr.control.Option.some(root.public_key());
        });
        assertEquals(java.util.List.of(7), requestedKeyIds);
        String datalog = token.print();
        assertTrue(datalog.contains("user(\"alice\")"), datalog);
        assertTrue(datalog.contains("scope(\"orders:read\")"), datalog);

        TokenPluginDescriptor descriptor = (TokenPluginDescriptor) generator.getPluginDescriptor();
        assertEquals(BiscuitTokenGenerator.TOKEN_TYPE, descriptor.getTokenType());
        assertTrue(descriptor.isSupportsExtendedContract());
    }
}
