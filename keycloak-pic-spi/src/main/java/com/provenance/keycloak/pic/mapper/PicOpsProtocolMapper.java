package com.provenance.keycloak.pic.mapper;

import com.provenance.keycloak.pic.PicConstants;
import com.provenance.keycloak.pic.exchange.OpsResolver;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Protocol mapper that adds the {@code pic_ops} claim to access tokens.
 *
 * <p>This mapper reads the user's PIC operations from user attributes
 * and adds them as a JSON array claim on the access token. This
 * enables the Federation Bridge ({@code provenance-bridge} JWT handler)
 * to extract PIC operations without requiring a full token exchange.
 *
 * <p>Configurable properties (set in Keycloak admin console):
 * <ul>
 *   <li>User attribute name (default: {@code "pic_ops"})</li>
 *   <li>Token claim name (default: {@code "pic_ops"})</li>
 *   <li>Add to access token (default: true)</li>
 *   <li>Add to ID token (default: false)</li>
 *   <li>Add to userinfo (default: false)</li>
 * </ul>
 *
 * <p><b>Registration:</b> Registered via Java ServiceLoader in
 * {@code META-INF/services/org.keycloak.protocol.ProtocolMapper}
 */
public class PicOpsProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    private static final Logger LOG = Logger.getLogger(PicOpsProtocolMapper.class);

    /**
     * Provider ID used for Keycloak's SPI registry.
     */
    public static final String PROVIDER_ID = "pic-ops-mapper";

    /**
     * Config key for the user attribute name containing PIC operations.
     */
    public static final String CONFIG_USER_ATTRIBUTE = "user.attribute";

    private static final String DISPLAY_TYPE = "PIC Operations";
    private static final String DISPLAY_CATEGORY = TOKEN_MAPPER_CATEGORY;
    private static final String HELP_TEXT =
            "Maps user's PIC operation attributes to a JWT claim as a JSON array.";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = new ArrayList<>();

        ProviderConfigProperty userAttrProp = new ProviderConfigProperty();
        userAttrProp.setName(CONFIG_USER_ATTRIBUTE);
        userAttrProp.setLabel("User Attribute");
        userAttrProp.setHelpText(
                "Name of the user attribute containing PIC operations. "
                + "Supports JSON array values, space-delimited values, "
                + "or multi-valued attributes.");
        userAttrProp.setType(ProviderConfigProperty.STRING_TYPE);
        userAttrProp.setDefaultValue(PicConstants.DEFAULT_OPS_USER_ATTRIBUTE);
        CONFIG_PROPERTIES.add(userAttrProp);

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(CONFIG_PROPERTIES);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES,
                PicOpsProtocolMapper.class);
    }

    private final OpsResolver opsResolver;

    public PicOpsProtocolMapper() {
        this.opsResolver = new OpsResolver();
    }

    // Visible for testing
    PicOpsProtocolMapper(OpsResolver opsResolver) {
        this.opsResolver = opsResolver;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getDisplayCategory() {
        return DISPLAY_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Sets the PIC ops claim on the token.
     *
     * <p>Reads the user's PIC operations from the configured user attribute,
     * parses them using {@link OpsResolver}, and sets the claim as a JSON
     * array on the token.
     *
     * @param token the token to modify
     * @param mappingModel the mapper configuration
     * @param userSession the user's session
     * @param keycloakSession the Keycloak session
     * @param clientSessionCtx the client session context
     */
    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {

        UserModel user = userSession.getUser();
        String userAttribute = mappingModel.getConfig().get(CONFIG_USER_ATTRIBUTE);
        if (userAttribute == null || userAttribute.isBlank()) {
            userAttribute = PicConstants.DEFAULT_OPS_USER_ATTRIBUTE;
        }

        // Read the user attribute values
        List<String> attrValues = user.getAttributeStream(userAttribute).toList();
        if (attrValues.isEmpty()) {
            LOG.debugv("No PIC ops found in user attribute '{0}' for user {1}",
                    userAttribute, user.getUsername());
            return;
        }

        // Parse using OpsResolver (handles JSON arrays, space-delimited, multi-valued)
        List<String> ops = opsResolver.parseUserOps(attrValues);
        if (ops.isEmpty()) {
            return;
        }

        LOG.debugv("PIC ops mapper: user={0}, attribute={1}, ops={2}",
                user.getUsername(), userAttribute, ops);

        // Set the claim directly on the token as a JSON array.
        // We bypass OIDCAttributeMapperHelper.mapClaim because it applies
        // mapAttributeValue which converts Lists to strings for non-JSON types.
        // PIC ops must always be a JSON array, not a string.
        String claimName = mappingModel.getConfig()
                .getOrDefault(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME,
                        PicConstants.CLAIM_PIC_OPS);
        token.getOtherClaims().put(claimName, ops);
    }
}
