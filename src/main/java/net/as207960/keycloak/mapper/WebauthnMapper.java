package net.as207960.keycloak.mapper;

import org.keycloak.models.*;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.List;
import java.util.ArrayList;

public class WebauthnMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {
    public static final String PROVIDER_ID = "oidc-webauthn-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, WebauthnMapper.class);
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Webauthn";
    }

    @Override
    public String getHelpText() {
        return "Adds a flag for the user having Webauthn and Webauthn passwordless configured";
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        boolean webauthTwoFactor = user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_TWOFACTOR);
        boolean webauthPasswordless = user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        token.getOtherClaims().put("webauthn_twofactor", webauthTwoFactor);
        token.getOtherClaims().put("webauthn_passwordless", webauthPasswordless);
    }
}