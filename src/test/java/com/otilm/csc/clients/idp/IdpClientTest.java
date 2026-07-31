package com.otilm.csc.clients.idp;

import com.otilm.csc.api.auth.JwksParser;
import com.otilm.csc.configuration.idp.IdpConfiguration;
import com.otilm.csc.model.UserInfo;
import com.otilm.csc.utils.configuration.IdpConfigurationBuilder;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.jsonwebtoken.security.PublicJwk;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static com.otilm.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = {IdpClient.class, JwksParser.class, IdpClientTest.IdpClientTestContext.class})
@Testcontainers
public class IdpClientTest {

    private static KeycloakContainer keycloak;


    @Autowired
    private IdpClient idpClient;

    @Autowired
    private JwksParser jwksParser;

    @BeforeAll
    public static void setup() {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.7.0")
                .withAdminUsername("admin")
                .withAdminPassword("pass");
        keycloak.start();
        issueFullAccessTokensForAdminCli();
    }

    /**
     * Keycloak enables lightweight access tokens on the {@code admin-cli} client by default, and the
     * userinfo endpoint rejects them with {@code "Lightweight access token not allowed for userinfo
     * endpoint"}. These tests mint their access token through {@code admin-cli}, so the flag is
     * turned off to obtain a full access token — the kind a real IDP client issues.
     */
    private static void issueFullAccessTokensForAdminCli() {
        try (Keycloak adminClient = keycloak.getKeycloakAdminClient()) {
            ClientsResource clients = adminClient.realm(KeycloakContainer.MASTER_REALM).clients();
            List<ClientRepresentation> found = clients.findByClientId(KeycloakContainer.ADMIN_CLI_CLIENT);
            if (found.isEmpty()) {
                throw new IllegalStateException(
                        "Keycloak returned no '" + KeycloakContainer.ADMIN_CLI_CLIENT + "' client in the '"
                                + KeycloakContainer.MASTER_REALM + "' realm, so the access token for these tests "
                                + "cannot be configured.");
            }
            ClientRepresentation adminCli = found.getFirst();
            Map<String, String> attributes = adminCli.getAttributes() == null
                    ? new HashMap<>()
                    : new HashMap<>(adminCli.getAttributes());
            attributes.put("client.use.lightweight.access.token.enabled", "false");
            adminCli.setAttributes(attributes);
            clients.get(adminCli.getId()).update(adminCli);
        }
    }

    @Test
    void downloadUserInfoReturnsUserInfo() {
        // when
        var getUserInfoResult = doWithAccessToken(token -> idpClient.downloadUserInfo(token));

        // then
        UserInfo userInfo = assertSuccessAndGet(getUserInfoResult);
        assertEquals(keycloak.getAdminUsername(), userInfo.getAttributes().get("preferred_username"));
    }

    @Test
    void downloadJwksReturnsJwks() {
        // given
        // IDP client setup

        // when
        var downloadResult = idpClient.downloadJwks();

        // then
        String token = assertSuccessAndGet(downloadResult);
        Set<PublicJwk<?>> parsed = jwksParser.parse(token).unwrap();
        assertEquals(2, parsed.size());
        boolean encKey = false;
        boolean sigKey = false;
        for (PublicJwk<?> jwk : parsed) {
            if (jwk.getPublicKeyUse().equals("enc")) encKey = true;
            if (jwk.getPublicKeyUse().equals("sig")) sigKey = true;
        }
        assertTrue(encKey);
        assertTrue(sigKey);
    }

    @Test
    void canDownloadUserInfoReturnsTrueWhenUserInfoUrlSpecified() {
        // given
        // IDP client setup

        // when
        boolean canDownloadUserInfo = idpClient.canDownloadUserInfo();

        // then
        assertTrue(canDownloadUserInfo);
    }

    @Test
    void canDownloadUserInfoReturnsFalseWhenUserInfoUrlNotSpecified() {
        // given
        IdpConfiguration idpConfiguration = IdpConfigurationBuilder.create()
                                                                   .withUserInfoUrl(null)
                                                                   .build();
        IdpClient idpClient = new IdpClient(idpConfiguration, null);

        // when
        boolean canDownloadUserInfo = idpClient.canDownloadUserInfo();

        // then
        assertFalse(canDownloadUserInfo);
    }

    private <T> T doWithAccessToken(Function<String, T> action) {
        KeycloakBuilder builder = KeycloakBuilder.builder()
                                                 .serverUrl(keycloak.getAuthServerUrl())
                                                 .realm(KeycloakContainer.MASTER_REALM)
                                                 .clientId(KeycloakContainer.ADMIN_CLI_CLIENT)
                                                 .username(keycloak.getAdminUsername())
                                                 .password(keycloak.getAdminPassword())
                                                 .scope("openid");
        try (Keycloak keycloakAdminClient = builder.build()) {
            String token = keycloakAdminClient.tokenManager().getAccessToken().getToken();
            return action.apply(token);
        }
    }

    public static class IdpClientTestContext {

        @Bean("idpClientRequestFactory")
        public HttpComponentsClientHttpRequestFactory requestFactory() {
            return new HttpComponentsClientHttpRequestFactory();
        }

        @Bean
        public IdpConfiguration idpConfiguration() {
            return IdpConfigurationBuilder.create()
                                          .withUserInfoUrl(
                                                  keycloak.getAuthServerUrl() + "/realms/master/protocol/openid-connect/userinfo")
                                          .withJwksUri(
                                                  keycloak.getAuthServerUrl() + "/realms/master/protocol/openid-connect/certs")
                                          .build();
        }
    }

}
