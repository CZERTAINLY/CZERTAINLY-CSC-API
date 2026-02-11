package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.utils.cert.CertificateUtils;
import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.crypto.FingerprintUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.KeyPair;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class MtlsAuthorizationFilterTest {

    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private ObjectMapper objectMapper;
    private FilterChain filterChain;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private final KeyPair trustedCaKeyPair = CertificateUtils.generateKeyPair();
    private final X509Certificate trustedCaCert = CertificateUtils.generateCaCertificate("CN=Trusted CA,O=Test", trustedCaKeyPair);
    private final KeyPair untrustedCaKeyPair = CertificateUtils.generateKeyPair();
    private final X509Certificate untrustedCaCert = CertificateUtils.generateCaCertificate("CN=Untrusted CA,O=Other", untrustedCaKeyPair);

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        filterChain = mock(FilterChain.class);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    // === Skip when no certificate ===

    @Test
    void shouldContinueFilterChainWhenNoCertificatePresent() throws Exception {
        // GIVEN — no cert attribute set (OAuth2 fallback scenario)
        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper, Set.of(), List.of(), List.of(), List.of("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"));

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void shouldContinueFilterChainWhenEmptyCertificateArray() throws Exception {
        // GIVEN
        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper, Set.of(), List.of(), List.of(), List.of("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"));
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[0]);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    // === Truststore checks ===

    @Test
    void shouldAcceptWhenCertIsTrustedByTruststore() throws Exception {
        // GIVEN
        X509Certificate clientCert = CertificateUtils.generateSignedCertificate("CN=Test User,O=Test", trustedCaKeyPair, trustedCaCert);
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(trustedCaCert, null));

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                trustAnchors,
                List.of(),
                List.of(),
                List.of()
        );

        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{clientCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void shouldRejectWhenCertIsNotTrustedByTruststore() throws Exception {
        // GIVEN
        X509Certificate clientCert = CertificateUtils.generateSignedCertificate("CN=Test User,O=Test", untrustedCaKeyPair, untrustedCaCert);

        // Truststore only contains the trusted CA, not the one that signed the client cert
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(trustedCaCert, null));

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                trustAnchors,
                List.of(),
                List.of(),
                List.of()
        );

        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{clientCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectWhenTruststoreCheckPassesButOtherCheckFails() throws Exception {
        // GIVEN
        KeyPair caKeyPair = CertificateUtils.generateKeyPair();
        X509Certificate caCert = CertificateUtils.generateCaCertificate("CN=Trusted CA,O=Test", caKeyPair);
        X509Certificate clientCert = CertificateUtils.generateSignedCertificate("CN=Test User,O=Test", caKeyPair, caCert);

        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(caCert, null));
        String wrongFingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                trustAnchors,
                List.of(),
                List.of(),
                List.of(wrongFingerprint)  // fingerprint won't match
        );

        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{clientCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN — truststore passes but fingerprint fails, so overall reject (AND logic)
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAcceptWhenCertChainIncludesTrustAnchorCert() throws Exception {
        // GIVEN — chain contains [endCert, caCert] where caCert IS the trust anchor.
        // PKIX requires the CertPath to exclude the trust anchor; the filter must strip it.
        X509Certificate clientCert = CertificateUtils.generateSignedCertificate("CN=Test User,O=Test", trustedCaKeyPair, trustedCaCert);
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(trustedCaCert, null));

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                trustAnchors,
                List.of(),
                List.of(),
                List.of()
        );

        // Chain includes the trust anchor cert (as Tomcat would forward it)
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{clientCert, trustedCaCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void shouldRejectWhenCertChainIncludesTrustAnchorButEndCertNotSignedByIt() throws Exception {
        // GIVEN — chain contains [endCert, trustedCaCert] but the end cert was signed by a different CA.
        X509Certificate clientCert = CertificateUtils.generateSignedCertificate("CN=Test User,O=Test", untrustedCaKeyPair, untrustedCaCert);
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(trustedCaCert, null));

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                trustAnchors,
                List.of(),
                List.of(),
                List.of()
        );

        // Chain includes the trusted CA cert, but the client cert was NOT signed by it
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{clientCert, trustedCaCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

    // === Issuer DN checks ===

    @Test
    void shouldRejectWhenIssuerNotInAllowedList() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSignedCertificate(
                "CN=Test User,O=Test Org",
                untrustedCaKeyPair,
                untrustedCaCert
        );
        X500Name allowedIssuer = CertificateUtils.getSubjectX500Name(trustedCaCert);

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),  // no truststore
                List.of(allowedIssuer),  // issuer check enabled
                List.of(),  // no subject check
                List.of()   // no fingerprint check
        );

        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

        ErrorDto error = objectMapper.readValue(response.getContentAsString(), ErrorDto.class);
        assertThat(error.error()).isEqualTo("forbidden");
        assertThat(error.errorDescription()).isEqualTo("Client certificate is not authorized for credential management.");

        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAcceptWhenIssuerInAllowedList() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSignedCertificate(
                "CN=Test User,O=Test Org",
                trustedCaKeyPair,
                trustedCaCert
        );
        X500Name allowedIssuer = CertificateUtils.getSubjectX500Name(trustedCaCert);

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(allowedIssuer),
                List.of(),
                List.of()
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldAcceptAnyIssuerWhenAllowedIssuersEmpty() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSignedCertificate(
                "CN=Test User,O=Test Org",
                untrustedCaKeyPair,
                untrustedCaCert
        );
        String correctFingerprint = FingerprintUtils.computeSha256Fingerprint(testCert);

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(),  // empty issuer list — skip check
                List.of(),
                List.of(correctFingerprint)  // at least one check must be configured
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        verify(filterChain).doFilter(request, response);
    }

    // === Subject DN checks ===

    @Test
    void shouldRejectWhenSubjectNotInAllowedList() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Unauthorized User,O=Bad Org"
        );
        X500Name allowedSubject = new X500Name("CN=Authorized User,O=Good Org");

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(),
                List.of(allowedSubject),  // subject check enabled
                List.of()
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAcceptWhenSubjectInAllowedList() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Authorized User,O=Good Org"
        );
        X500Name allowedSubject = new X500Name("CN=Authorized User,O=Good Org");

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(),
                List.of(allowedSubject),
                List.of()
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        verify(filterChain).doFilter(request, response);
    }

    // === Fingerprint checks ===

    @Test
    void shouldRejectWhenFingerprintNotInAllowedList() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Test User,O=Test Org"
        );
        String wrongFingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(),
                List.of(),
                List.of(wrongFingerprint)  // fingerprint check enabled with the wrong fingerprint
        );
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAcceptWhenFingerprintInAllowedList() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Test User,O=Test Org"
        );
        String correctFingerprint = FingerprintUtils.computeSha256Fingerprint(testCert);

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(),
                List.of(),
                List.of(correctFingerprint)
        );

        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        verify(filterChain).doFilter(request, response);
    }

    // === AND logic ===

    @Test
    void shouldRejectWhenIssuerMatchesButFingerprintDoesNot() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSignedCertificate(
                "CN=Test User,O=Test Org",
                untrustedCaKeyPair,
                untrustedCaCert
        );
        X500Name allowedIssuer = CertificateUtils.getSubjectX500Name(trustedCaCert);
        String wrongFingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(allowedIssuer),  // issuer matches
                List.of(),
                List.of(wrongFingerprint)  // fingerprint doesn't match
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void shouldAcceptWhenAllConfiguredChecksPassed() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSignedCertificate(
                "CN=Test User,O=Test Org",
                trustedCaKeyPair,
                trustedCaCert
        );
        X500Name allowedIssuer = CertificateUtils.getSubjectX500Name(trustedCaCert);
        X500Name allowedSubject = CertificateUtils.getSubjectX500Name(testCert);
        String correctFingerprint = FingerprintUtils.computeSha256Fingerprint(testCert);

        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(trustedCaCert, null));
        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                trustAnchors,
                List.of(allowedIssuer),
                List.of(allowedSubject),
                List.of(correctFingerprint)
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        verify(filterChain).doFilter(request, response);
    }

    // === Safety guard ===

    @Test
    void shouldRejectWhenNoChecksConfigured() throws Exception {
        // GIVEN - all check lists empty, no trust anchors
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Test User,O=Test Org"
        );

        MtlsAuthorizationFilter filter = new MtlsAuthorizationFilter(
                objectMapper,
                Set.of(),
                List.of(),
                List.of(),
                List.of()
        );


        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verify(filterChain, never()).doFilter(any(), any());
    }

}
