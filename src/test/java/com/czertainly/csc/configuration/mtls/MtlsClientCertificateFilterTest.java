package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.utils.cert.CertificateUtils;
import com.czertainly.csc.api.common.ErrorDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class MtlsClientCertificateFilterTest {

    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private ObjectMapper objectMapper;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        filterChain = mock(FilterChain.class);
    }

    // === Certificate-only mode (no fallback) ===

    @Test
    void shouldReturn401WhenNoCertificatePresentAndNoFallback() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

        ErrorDto error = objectMapper.readValue(response.getContentAsString(), ErrorDto.class);
        assertThat(error.error()).isEqualTo("unauthorized");
        assertThat(error.errorDescription()).isEqualTo("Client certificate is required.");

        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldReturn401WhenEmptyCertificateArrayAndNoFallback() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[0]);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

        ErrorDto error = objectMapper.readValue(response.getContentAsString(), ErrorDto.class);
        assertThat(error.error()).isEqualTo("unauthorized");
        assertThat(error.errorDescription()).isEqualTo("Client certificate is required.");

        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldContinueFilterChainWhenCertificatePresent() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate("CN=Test User,O=Test Org");
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    // === Fallback to OAuth2 mode ===

    @Test
    void shouldContinueFilterChainWhenNoCertificateAndFallbackEnabled() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, true, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void shouldContinueFilterChainWhenEmptyCertArrayAndFallbackEnabled() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, true, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[0]);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    // === Certificate from header (proxy mode) ===

    @Test
    void shouldExtractPemCertificateFromHeader() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate("CN=Proxy User,O=Test Org");
        String pem = "-----BEGIN CERTIFICATE-----\n"
                     + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(testCert.getEncoded())
                     + "\n-----END CERTIFICATE-----";

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", pem);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);
        assertThat(certs).isNotNull().hasSize(1);
        assertThat(certs[0].getSubjectX500Principal().getName()).contains("CN=Proxy User");
    }

    @Test
    void shouldExtractPemCertificateChainFromHeader() throws Exception {
        // GIVEN — PEM chain with end-entity + CA cert
        KeyPair caKeyPair = CertificateUtils.generateKeyPair();
        X509Certificate caCert = CertificateUtils.generateCaCertificate("CN=Test CA,O=Test Org", caKeyPair);
        X509Certificate endEntityCert = CertificateUtils.generateSignedCertificate("CN=Proxy User,O=Test Org", caKeyPair, caCert);

        String pemChain = "-----BEGIN CERTIFICATE-----\n"
                          + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(endEntityCert.getEncoded())
                          + "\n-----END CERTIFICATE-----\n"
                          + "-----BEGIN CERTIFICATE-----\n"
                          + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(caCert.getEncoded())
                          + "\n-----END CERTIFICATE-----";

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", pemChain);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);
        assertThat(certs).isNotNull().hasSize(2);
        assertThat(certs[0].getSubjectX500Principal().getName()).contains("CN=Proxy User");
        assertThat(certs[1].getSubjectX500Principal().getName()).contains("CN=Test CA");
    }

    @Test
    void shouldReverseCertificateChainWhenCaIsFirst() throws Exception {
        // GIVEN — PEM chain in reverse order: CA first, end-entity last
        KeyPair caKeyPair = CertificateUtils.generateKeyPair();
        X509Certificate caCert = CertificateUtils.generateCaCertificate("CN=Test CA,O=Test Org", caKeyPair);
        X509Certificate endEntityCert = CertificateUtils.generateSignedCertificate("CN=Proxy User,O=Test Org", caKeyPair, caCert);

        String pemChain = toPem(caCert) + "\n" + toPem(endEntityCert);

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", pemChain);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN — chain should be reversed so end-entity is first
        verify(filterChain).doFilter(request, response);
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);
        assertThat(certs).isNotNull().hasSize(2);
        assertThat(certs[0].getSubjectX500Principal().getName()).contains("CN=Proxy User");
        assertThat(certs[1].getSubjectX500Principal().getName()).contains("CN=Test CA");
    }

    @Test
    void shouldReturn401WhenChainHasNeitherEndEntityFirstNorLast() throws Exception {
        // GIVEN — chain of only CA certs (no end-entity at either end)
        KeyPair caKeyPair1 = CertificateUtils.generateKeyPair();
        X509Certificate caCert1 = CertificateUtils.generateCaCertificate("CN=CA One,O=Test Org", caKeyPair1);
        KeyPair caKeyPair2 = CertificateUtils.generateKeyPair();
        X509Certificate caCert2 = CertificateUtils.generateCaCertificate("CN=CA Two,O=Test Org", caKeyPair2);

        String pemChain = toPem(caCert1) + "\n" + toPem(caCert2);

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", pemChain);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN — should fail because neither end is an end-entity
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldReturn401WhenHeaderContainsInvalidCertAndNoFallback() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", "not-a-valid-certificate");

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldFallbackToOAuth2WhenHeaderContainsInvalidCertAndFallbackEnabled() throws Exception {
        // GIVEN
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, true, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", "not-a-valid-certificate");

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void shouldPreferTlsCertOverHeaderCert() throws Exception {
        // GIVEN — both TLS and header certs present; TLS should take precedence
        X509Certificate tlsCert = CertificateUtils.generateSelfSignedCertificate("CN=TLS User,O=Test Org");
        X509Certificate headerCert = CertificateUtils.generateSelfSignedCertificate("CN=Header User,O=Test Org");
        String pem = "-----BEGIN CERTIFICATE-----\n"
                     + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(headerCert.getEncoded())
                     + "\n-----END CERTIFICATE-----";

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{tlsCert});
        request.addHeader("X-SSL-Client-Cert", pem);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN — TLS cert should be used, not header cert
        verify(filterChain).doFilter(request, response);
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);
        assertThat(certs[0].getSubjectX500Principal().getName()).contains("CN=TLS User");
    }

    @Test
    void shouldExtractCertificateFromBase64DerWithoutPemHeaders() throws Exception {
        // GIVEN — raw Base64-encoded DER (no PEM headers)
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate("CN=DER User,O=Test Org");
        String base64Der = Base64.getEncoder().encodeToString(testCert.getEncoded());

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", base64Der);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN — fallback to Base64 DER parsing should succeed
        verify(filterChain).doFilter(request, response);
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);
        assertThat(certs).isNotNull().hasSize(1);
        assertThat(certs[0].getSubjectX500Principal().getName()).contains("CN=DER User");
    }

    // === Certificate expiration validation ===

    @Test
    void shouldRejectExpiredPemCertificateFromHeader() throws Exception {
        // GIVEN
        X509Certificate expiredCert = CertificateUtils.generateExpiredCertificate("CN=Expired User,O=Test Org");
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", toPem(expiredCert));

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectNotYetValidPemCertificateFromHeader() throws Exception {
        // GIVEN
        X509Certificate notYetValidCert = CertificateUtils.generateNotYetValidCertificate("CN=Future User,O=Test Org");
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", toPem(notYetValidCert));

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectExpiredBase64DerCertificateFromHeader() throws Exception {
        // GIVEN
        X509Certificate expiredCert = CertificateUtils.generateExpiredCertificate("CN=Expired DER User,O=Test Org");
        String base64Der = Base64.getEncoder().encodeToString(expiredCert.getEncoded());
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", base64Der);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldFallbackToOAuth2WhenExpiredCertInHeaderAndFallbackEnabled() throws Exception {
        // GIVEN
        X509Certificate expiredCert = CertificateUtils.generateExpiredCertificate("CN=Expired User,O=Test Org");
        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, true, "X-SSL-Client-Cert");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-SSL-Client-Cert", toPem(expiredCert));

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(request.getAttribute(CERT_ATTRIBUTE)).isNull();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    // === TLS handshake end-entity validation ===

    @Test
    void shouldRejectRequestWhenTlsCertificateIsNotEndEntity() throws Exception {
        // GIVEN — a CA certificate presented in TLS handshake (not an end-entity)
        KeyPair caKeyPair = CertificateUtils.generateKeyPair();
        X509Certificate caCert = CertificateUtils.generateCaCertificate("CN=Test CA,O=Test Org", caKeyPair);

        MtlsClientCertificateFilter filter = new MtlsClientCertificateFilter(objectMapper, false, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{caCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN — filter should reject the request and not continue the chain
        verify(filterChain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
               + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
               + "\n-----END CERTIFICATE-----";
    }
}
