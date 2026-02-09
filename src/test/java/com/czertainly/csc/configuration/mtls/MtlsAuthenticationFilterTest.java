package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.utils.cert.CertificateUtils;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.cert.X509Certificate;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class MtlsAuthenticationFilterTest {

    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private MtlsAuthenticationFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new MtlsAuthenticationFilter();
        filterChain = mock(FilterChain.class);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldContinueWithoutSettingSecurityContextWhenNoCertificate() throws Exception {
        // GIVEN — no cert attribute (OAuth2 fallback scenario)
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldContinueWithoutSettingSecurityContextWhenEmptyCertArray() throws Exception {
        // GIVEN
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[0]);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldSetSecurityContextWithManageCredentialsScope() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Test User,O=Test Org"
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication).isInstanceOf(MtlsAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isTrue();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        assertThat(authorities).hasSize(1);
        assertThat(authorities.iterator().next().getAuthority()).isEqualTo("SCOPE_manageCredentials");

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldSetCertificateSubjectAsPrincipal() throws Exception {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Admin User,O=Management Org,C=US"
        );
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setAttribute(CERT_ATTRIBUTE, new X509Certificate[]{testCert});

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        Object principal = authentication.getPrincipal();
        assertThat(principal).isInstanceOf(String.class);
        String subjectDn = (String) principal;
        assertThat(subjectDn).contains("CN=Admin User");
        assertThat(subjectDn).contains("O=Management Org");

        // Verify the cert is accessible via the token
        MtlsAuthenticationToken token = (MtlsAuthenticationToken) authentication;
        assertThat(token.getCertificate()).isEqualTo(testCert);
        assertThat(token.getCredentials()).isEqualTo(testCert);
    }
}
