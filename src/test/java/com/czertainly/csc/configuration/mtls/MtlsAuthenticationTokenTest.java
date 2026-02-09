package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.utils.cert.CertificateUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MtlsAuthenticationTokenTest {

    @Test
    void shouldReturnSubjectDnAsPrincipal() {
        // GIVEN
        String subjectDn = "CN=Test User,O=Test Org";
        X509Certificate cert = CertificateUtils.generateSelfSignedCertificate(subjectDn);
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("SCOPE_test"));

        // WHEN
        MtlsAuthenticationToken token = new MtlsAuthenticationToken(subjectDn, cert, authorities);

        // THEN
        assertThat(token.getPrincipal()).isEqualTo(subjectDn);
    }

    @Test
    void shouldReturnCertificateAsCredentials() {
        // GIVEN
        String subjectDn = "CN=Test User,O=Test Org";
        X509Certificate cert = CertificateUtils.generateSelfSignedCertificate(subjectDn);
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("SCOPE_test"));

        // WHEN
        MtlsAuthenticationToken token = new MtlsAuthenticationToken(subjectDn, cert, authorities);

        // THEN
        assertThat(token.getCredentials()).isEqualTo(cert);
        assertThat(token.getCertificate()).isEqualTo(cert);
    }

    @Test
    void shouldBeAuthenticated() {
        // GIVEN
        String subjectDn = "CN=Test User,O=Test Org";
        X509Certificate cert = CertificateUtils.generateSelfSignedCertificate(subjectDn);
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("SCOPE_test"));

        // WHEN
        MtlsAuthenticationToken token = new MtlsAuthenticationToken(subjectDn, cert, authorities);

        // THEN
        assertThat(token.isAuthenticated()).isTrue();
    }

    @Test
    void shouldContainGrantedAuthorities() {
        // GIVEN
        String subjectDn = "CN=Test User,O=Test Org";
        X509Certificate cert = CertificateUtils.generateSelfSignedCertificate(subjectDn);
        GrantedAuthority authority1 = new SimpleGrantedAuthority("SCOPE_read");
        GrantedAuthority authority2 = new SimpleGrantedAuthority("SCOPE_write");
        List<GrantedAuthority> authorities = List.of(authority1, authority2);

        // WHEN
        MtlsAuthenticationToken token = new MtlsAuthenticationToken(subjectDn, cert, authorities);

        // THEN
        assertThat(token.getAuthorities()).hasSize(2);
        assertThat(token.getAuthorities()).contains(authority1, authority2);
    }
}
