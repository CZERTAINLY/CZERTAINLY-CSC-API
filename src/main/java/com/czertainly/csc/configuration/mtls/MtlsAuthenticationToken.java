package com.czertainly.csc.configuration.mtls;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;


/**
 * Spring Security authentication token representing a successfully authenticated mTLS client.
 * Holds the client certificate's subject DN as the principal and the {@link X509Certificate}
 * itself as the credentials. Created by {@link MtlsAuthenticationFilter} after the certificate
 * has passed all authorization checks.
 *
 * <p>Granted authorities are synthetic (e.g. {@code SCOPE_manageCredentials}) so that
 * existing {@code @PreAuthorize} annotations on controllers work without modification.
 */
public class MtlsAuthenticationToken extends AbstractAuthenticationToken {

    private final String subjectDn;
    private final X509Certificate certificate;

    public MtlsAuthenticationToken(String subjectDn,
                                   X509Certificate certificate,
                                   Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.subjectDn = subjectDn;
        this.certificate = certificate;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return certificate;
    }

    @Override
    public Object getPrincipal() {
        return subjectDn;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        MtlsAuthenticationToken that = (MtlsAuthenticationToken) o;
        return Objects.equals(subjectDn, that.subjectDn) && Objects.equals(certificate, that.certificate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), subjectDn, certificate);
    }
}
