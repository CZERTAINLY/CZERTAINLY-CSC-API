package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ssl.SslBundles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class ManagementMtlsSecurityConfigurationTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SslBundles sslBundles = mock(SslBundles.class);

    @Test
    void shouldFailToStartWhenNoAuthorizationChecksConfigured() {
        // GIVEN - all authorization checks are empty/null
        ManagementMtlsProperties emptyMtlsProps = new ManagementMtlsProperties(
                null, List.of(), List.of(), List.of(), null);
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE, emptyMtlsProps);

        // WHEN & THEN
        assertThatThrownBy(() -> new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles))
                .isInstanceOf(ApplicationConfigurationException.class)
                .hasMessageContaining("no authorization checks are configured")
                .hasMessageContaining("Refusing to start to prevent accidental open access");
    }

    @Test
    void shouldFailToStartWhenNoAuthorizationChecksConfiguredForCertificateOauth2() {
        // GIVEN
        ManagementMtlsProperties emptyMtlsProps = new ManagementMtlsProperties(
                null, List.of(), List.of(), List.of(), null);
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE_OAUTH2, emptyMtlsProps);

        // WHEN & THEN
        assertThatThrownBy(() -> new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles))
                .isInstanceOf(ApplicationConfigurationException.class)
                .hasMessageContaining("no authorization checks are configured");
    }

    @Test
    void shouldStartSuccessfullyWithAllowedIssuersOnly() {
        // GIVEN
        ManagementMtlsProperties mtlsProps = new ManagementMtlsProperties(
                null, List.of("CN=Trusted CA,O=Test Org"), List.of(), List.of(), null);
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE, mtlsProps);

        // WHEN & THEN - should not throw
        ManagementMtlsSecurityConfiguration config = new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles);
        assertThat(config).isNotNull();
    }

    @Test
    void shouldStartSuccessfullyWithAllowedSubjectsOnly() {
        // GIVEN
        ManagementMtlsProperties mtlsProps = new ManagementMtlsProperties(
                null, List.of(), List.of("CN=Admin User,O=Test Org"), List.of(), null);
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE, mtlsProps);

        // WHEN & THEN - should not throw
        ManagementMtlsSecurityConfiguration config = new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles);
        assertThat(config).isNotNull();
    }

    @Test
    void shouldStartSuccessfullyWithAllowedFingerprintsOnly() {
        // GIVEN
        ManagementMtlsProperties mtlsProps = new ManagementMtlsProperties(
                null, List.of(), List.of(),
                List.of("A1:B2:C3:D4:E5:F6:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"),
                null);
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE, mtlsProps);

        // WHEN & THEN - should not throw
        ManagementMtlsSecurityConfiguration config = new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles);
        assertThat(config).isNotNull();
    }

    @Test
    void shouldStartSuccessfullyWithCertificateOauth2ModeAndSslDisabled() {
        // GIVEN — SSL disabled (behind reverse proxy), CERTIFICATE_OAUTH2 mode
        ManagementMtlsProperties mtlsProps = new ManagementMtlsProperties(
                null, List.of("CN=Trusted CA,O=Test Org"), List.of(), List.of(), "X-SSL-Client-Cert");
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE_OAUTH2, mtlsProps);

        // WHEN & THEN - should not throw
        ManagementMtlsSecurityConfiguration config = new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles);
        assertThat(config).isNotNull();
    }

    @Test
    void shouldStartSuccessfullyWithCertificateOnlyModeAndSslDisabled() {
        // GIVEN — SSL disabled but cert-only mode (proxy provides cert via header)
        ManagementMtlsProperties mtlsProps = new ManagementMtlsProperties(
                null, List.of("CN=Trusted CA,O=Test Org"), List.of(), List.of(), "X-SSL-Client-Cert");
        ManagementAuthConfiguration authConfig = new ManagementAuthConfiguration(
                ManagementAuthType.CERTIFICATE, mtlsProps);

        // WHEN & THEN - should not throw
        ManagementMtlsSecurityConfiguration config = new ManagementMtlsSecurityConfiguration(
                authConfig, objectMapper, sslBundles);
        assertThat(config).isNotNull();
    }
}
