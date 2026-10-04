package com.darkedges.pingfederate.biscuit;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.wstrust.model.BinarySecurityToken;
import org.sourceid.wstrust.plugin.TokenProcessingException;
import org.sourceid.wstrust.plugin.generate.TokenContext;
import org.sourceid.wstrust.plugin.generate.TokenGenerator;
import org.sourceid.wstrust.plugin.process.TokenPluginDescriptor;

import com.pingidentity.common.util.xml.XmlIDUtil;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;

/**
 * PingFederate token generator that mints Biscuit tokens.
 *
 * <p>Wire it up as the generator for an OAuth Token Exchange (RFC 8693) generator group, so a client presents a
 * PingFederate-issued JWT as {@code subject_token} with {@code requested_token_type=}{@value #TOKEN_TYPE} and
 * receives a Biscuit whose authority block carries the mapped attributes.
 */
public class BiscuitTokenGenerator implements TokenGenerator
{
    public static final String TOKEN_TYPE = "urn:darkedges:params:oauth:token-type:biscuit";

    static final String NAME = "Biscuit Token Generator";
    static final String FIELD_ROOT_KEY = "Root Private Key";
    static final String FIELD_ROOT_KEY_ID = "Root Key ID";
    static final String FIELD_ISSUER = "Issuer";
    static final String FIELD_LIFETIME = "Token Lifetime (seconds)";
    static final String FIELD_AUDIENCES = "Audiences";
    static final String FIELD_FACT_ATTRIBUTES = "Fact Attributes";

    private static final Logger LOG = Logger.getLogger(BiscuitTokenGenerator.class.getName());

    private final TokenPluginDescriptor descriptor;
    private BiscuitMinter minter;

    public BiscuitTokenGenerator()
    {
        GuiConfigDescriptor gui = new GuiConfigDescriptor(
                "Mints Biscuit tokens (Datalog authority block, Ed25519) from the token exchange attribute contract.");

        TextFieldDescriptor rootKey = new TextFieldDescriptor(FIELD_ROOT_KEY,
                "Hex-encoded Ed25519 private key (32 bytes). Generate with: java -jar <plugin>.jar keygen", true);
        rootKey.addValidator(new RequiredFieldValidator());
        gui.addField(rootKey);

        TextFieldDescriptor rootKeyId = new TextFieldDescriptor(FIELD_ROOT_KEY_ID,
                "Optional integer written to the token so verifiers can pick the right public key during rotation.");
        rootKeyId.addValidator(new IntegerValidator(), true);
        gui.addField(rootKeyId);

        TextFieldDescriptor issuer = new TextFieldDescriptor(FIELD_ISSUER,
                "Emitted as the issuer(...) fact, typically the PingFederate base URL.");
        issuer.addValidator(new RequiredFieldValidator());
        gui.addField(issuer);

        TextFieldDescriptor lifetime = new TextFieldDescriptor(FIELD_LIFETIME,
                "Emitted as check if time($t), $t <= now + lifetime.");
        lifetime.setDefaultValue("300");
        lifetime.addValidator(new IntegerValidator(1, 86400));
        gui.addField(lifetime);

        TextFieldDescriptor audiences = new TextFieldDescriptor(FIELD_AUDIENCES,
                "Comma-separated. Emitted as check if audience($a), {...}.contains($a). Leave blank for no audience check.");
        gui.addField(audiences);

        TextFieldDescriptor factAttributes = new TextFieldDescriptor(FIELD_FACT_ATTRIBUTES,
                "Comma-separated contract attributes that become authority facts (subject->user, client_id->client).");
        factAttributes.setDefaultValue("subject,client_id,scope,group,amr");
        gui.addField(factAttributes);

        Set<String> contract = Set.of("subject");
        descriptor = new TokenPluginDescriptor(NAME, this, gui, TOKEN_TYPE, contract);
        descriptor.setSupportsExtendedContract(true);
    }

    @Override
    public void configure(Configuration configuration)
    {
        String rootKeyHex = configuration.getFieldValue(FIELD_ROOT_KEY);
        String rootKeyId = trimToNull(configuration.getFieldValue(FIELD_ROOT_KEY_ID));
        String lifetime = trimToNull(configuration.getFieldValue(FIELD_LIFETIME));

        minter = BiscuitMinter.builder()
                .rootKey(new KeyPair(rootKeyHex.trim()))
                .rootKeyId(rootKeyId == null ? null : Integer.valueOf(rootKeyId))
                .issuer(configuration.getFieldValue(FIELD_ISSUER).trim())
                .lifetime(Duration.ofSeconds(lifetime == null ? 300 : Long.parseLong(lifetime)))
                .audiences(csv(configuration.getFieldValue(FIELD_AUDIENCES)))
                .factAttributes(csv(configuration.getFieldValue(FIELD_FACT_ATTRIBUTES)))
                .build();
    }

    @Override
    public BinarySecurityToken generateToken(TokenContext context) throws TokenProcessingException
    {
        Map<String, AttributeValue> attributes = context.getSubjectAttributes();
        if (attributes == null || attributes.get("subject") == null)
        {
            throw new TokenProcessingException("Biscuit generator requires a 'subject' attribute", null);
        }

        Map<String, Collection<String>> flat = new HashMap<>();
        for (Map.Entry<String, AttributeValue> e : attributes.entrySet())
        {
            if (e.getValue() != null)
            {
                flat.put(e.getKey(), e.getValue().getValuesAsCollection());
            }
        }

        try
        {
            BiscuitMinter.Minted minted = minter.mint(flat);
            // The authority revocation ID kills this token and every attenuated descendant;
            // log it with the subject so an operator can revoke it later.
            LOG.info(() -> "Minted biscuit subject=" + attributes.get("subject").getValue()
                    + " expires=" + minted.expiresAt() + " revocation_id=" + minted.revocationIds().get(0));

            // PingFederate's token exchange endpoint returns getEncodedData() verbatim as access_token and
            // derives expires_in from the expiry date, so the Biscuit's native base64url form goes straight out.
            BinarySecurityToken bst = new BinarySecurityToken(XmlIDUtil.createID(), TOKEN_TYPE);
            bst.setEncodingType(BinarySecurityToken.BASE64_URL_ENCODING_TYPE);
            bst.setEncodedData(minted.token());
            bst.setCreatedDate(new Date());
            bst.setExpiryDate(Date.from(minted.expiresAt()));
            return bst;
        }
        catch (Exception e)
        {
            throw new TokenProcessingException("Unable to mint biscuit: " + e.getMessage(), e);
        }
    }

    @Override
    public PluginDescriptor getPluginDescriptor()
    {
        return descriptor;
    }

    private static List<String> csv(String value)
    {
        if (value == null || value.isBlank())
        {
            return List.of();
        }
        return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
    }

    private static String trimToNull(String value)
    {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
