package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.assertNotNull;

public class UaaSamlIdpCreator implements SamlIdentityProviderCreator {
    @Override
    public IdentityProvider<SamlIdentityProviderDefinition> createIdp(String baseUrl) {
        String zoneAdminToken = getZoneAdminToken(baseUrl, ServerRunning.isRunning());
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createDefinition();
        return createIdentityProvider("UAA test idp", baseUrl);
    }

    private SamlIdentityProviderDefinition createDefinition() {

        return null;
    }

    private IdentityProvider createIdentityProvider(String name,
                                                    String baseUrl) {


        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createDefinition();
        String zoneAdminToken = getZoneAdminToken(baseUrl, ServerRunning.isRunning());

        samlIdentityProviderDefinition.setAddShadowUserOnLogin(true);
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName(name);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertNotNull(provider.getId());
        return provider;
    }

    private String getZoneAdminToken(String baseUrl, ServerRunning serverRunning) {
        try {
            return getZoneAdminToken(baseUrl, serverRunning, OriginKeys.UAA);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getZoneAdminToken(String baseUrl, ServerRunning serverRunning, String zoneId) throws Exception {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        return IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
            UaaTestAccounts.standard(serverRunning),
            "identity",
            "identitysecret",
            email,
            "secr3T");
    }
}
