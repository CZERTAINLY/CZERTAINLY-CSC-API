package com.czertainly.csc.configuration.mtls;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Servlet filter that populates the Spring {@link SecurityContextHolder} with an
 * {@link MtlsAuthenticationToken} built from the client certificate. Grants the
 * {@code SCOPE_manageCredentials} authority so that existing {@code @PreAuthorize}
 * annotations on management controllers are satisfied without changes.
 *
 * <p>Must be placed after {@link MtlsClientCertificateFilter} and
 * {@link MtlsAuthorizationFilter}, which guarantee that the certificate is present
 * and authorized before this filter runs.
 */
public class MtlsAuthenticationFilter extends OncePerRequestFilter {

    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
    private static final String MANAGEMENT_SCOPE = "SCOPE_manageCredentials";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);

        // No certificate — skip mTLS authentication (OAuth2 will handle it downstream)
        if (certs == null || certs.length == 0) {
            filterChain.doFilter(request, response);
            return;
        }

        X509Certificate clientCert = certs[0];

        String subjectDn = clientCert.getSubjectX500Principal().getName();

        MtlsAuthenticationToken authentication = new MtlsAuthenticationToken(
                subjectDn,
                clientCert,
                List.of(new SimpleGrantedAuthority(MANAGEMENT_SCOPE))
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
