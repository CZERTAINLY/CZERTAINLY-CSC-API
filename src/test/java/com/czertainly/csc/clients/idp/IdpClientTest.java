package com.czertainly.csc.clients.idp;

import com.czertainly.csc.api.auth.JwksParser;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import com.czertainly.csc.model.UserInfo;
import com.czertainly.csc.utils.configuration.IdpConfigurationBuilder;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.jsonwebtoken.security.PublicJwk;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Set;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
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
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.0")
                .withAdminUsername("admin")
                .withAdminPassword("pass");
        keycloak.start();
    }

    @Test
    void downloadUserInfoReturnsUserInfo() {
        // given
        String token = obtainAccessToken();

        // when
        var getUserInfoResult = idpClient.downloadUserInfo(token);

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

    private String obtainAccessToken() {
        KeycloakBuilder builder = KeycloakBuilder.builder()
                                                 .serverUrl(keycloak.getAuthServerUrl())
                                                 .realm(KeycloakContainer.MASTER_REALM)
                                                 .clientId(KeycloakContainer.ADMIN_CLI_CLIENT)
                                                 .username(keycloak.getAdminUsername())
                                                 .password(keycloak.getAdminPassword())
                                                 .scope("openid");
        try (Keycloak keycloakAdminClient = builder.build()) {
            return keycloakAdminClient.tokenManager().getAccessToken().getToken();
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
                                          .withUserInfoUrl(keycloak.getAuthServerUrl() + "/realms/master/protocol/openid-connect/userinfo")
                                          .withJwksUri(keycloak.getAuthServerUrl() + "/realms/master/protocol/openid-connect/certs")
                                          .build();
        }
    }

}
