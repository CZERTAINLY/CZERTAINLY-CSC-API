package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.crypto.FingerprintUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import org.bouncycastle.pkix.jcajce.CertPathReviewerException;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;

import java.io.IOException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;


/**
 * Servlet filter that authorizes a client certificate against configurable checks.
 * Returns 403 Forbidden if any enabled check fails. All configured checks use AND logic —
 * every enabled check must pass for the request to proceed.
 *
 * <p>Supported checks (each skipped when not configured):
 * <ul>
 *   <li><b>Truststore</b> — PKIX chain validation against a dedicated set of trust anchors</li>
 *   <li><b>Issuer DN</b> — certificate issuer must match one of the allowed issuers</li>
 *   <li><b>Subject DN</b> — a certificate subject must match one of the allowed subjects</li>
 *   <li><b>Fingerprint</b> — SHA-256 fingerprint must match one of the pinned values</li>
 * </ul>
 *
 * <p>Must be placed after {@link MtlsClientCertificateFilter}. Skips processing when no
 * certificate is present (allowing downstream OAuth2 authentication to handle the request).
 */
public class MtlsAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(MtlsAuthorizationFilter.class);
    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final ObjectMapper objectMapper;
    private final Set<TrustAnchor> trustAnchors;
    private final List<X500Name> allowedIssuers;
    private final List<X500Name> allowedSubjects;
    private final List<String> allowedFingerprints;

    public MtlsAuthorizationFilter(
            @NonNull ObjectMapper objectMapper,
            @NonNull Set<TrustAnchor> trustAnchors,
            @NonNull List<X500Name> allowedIssuers,
            @NonNull List<X500Name> allowedSubjects,
            @NonNull List<String> allowedFingerprints
    ) {
        this.objectMapper = objectMapper;
        this.trustAnchors = trustAnchors;
        this.allowedIssuers = allowedIssuers;
        this.allowedSubjects = allowedSubjects;
        this.allowedFingerprints = FingerprintUtils.normalizeFingerprints(allowedFingerprints);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);

        // No certificate — skip mTLS authorization (OAuth2 will handle authentication downstream)
        if (certs == null || certs.length == 0) {
            filterChain.doFilter(request, response);
            return;
        }

        X509Certificate clientCert = certs[0];

        String subjectDn = clientCert.getSubjectX500Principal().getName();
        String issuerDn = clientCert.getIssuerX500Principal().getName();
        String fingerprint = FingerprintUtils.computeSha256Fingerprint(clientCert);

        List<String> passedChecks = new ArrayList<>();

        // 1. Truststore bundle check (PKIX chain validation)
        if (!trustAnchors.isEmpty()) {
            if (!validateCertChain(certs)) {
                logger.warn("Management mTLS authorization REJECTED — "
                                + "cert chain not trusted by certificate management truststore. "
                                + "Subject: [{}], Issuer: [{}], Fingerprint: [{}]",
                        subjectDn, issuerDn, fingerprint);
                writeErrorResponse(response);
                return;
            }
            passedChecks.add("truststoreBundle");
        }

        // 2. Issuer DN check
        if (!allowedIssuers.isEmpty()) {
            X500Name certIssuer = X500Name.getInstance(ASN1Sequence.getInstance(clientCert.getIssuerX500Principal().getEncoded()));
            boolean issuerMatch = allowedIssuers.stream().anyMatch(allowed -> allowed.equals(certIssuer));
            if (!issuerMatch) {
                logger.warn("Management mTLS authorization REJECTED — "
                                + "issuer DN not in allowedIssuers. "
                                + "Subject: [{}], Issuer: [{}], Fingerprint: [{}]",
                        subjectDn, issuerDn, fingerprint);
                writeErrorResponse(response);
                return;
            }
            passedChecks.add("allowedIssuers");
        }

        // 3. Subject DN check
        if (!allowedSubjects.isEmpty()) {
            X500Name certSubject = X500Name.getInstance(ASN1Sequence.getInstance(clientCert.getSubjectX500Principal().getEncoded()));
            boolean subjectMatch = allowedSubjects.stream().anyMatch(allowed -> allowed.equals(certSubject));
            if (!subjectMatch) {
                logger.warn("Management mTLS authorization REJECTED — "
                                + "subject DN not in allowedSubjects. "
                                + "Subject: [{}], Issuer: [{}], Fingerprint: [{}]",
                        subjectDn, issuerDn, fingerprint);
                writeErrorResponse(response);
                return;
            }
            passedChecks.add("allowedSubjects");
        }

        // 4. Fingerprint check
        if (!allowedFingerprints.isEmpty()) {
            if (!allowedFingerprints.contains(fingerprint)) {
                logger.warn("Management mTLS authorization REJECTED — "
                                + "fingerprint not in allowedFingerprints. "
                                + "Subject: [{}], Issuer: [{}], Fingerprint: [{}]",
                        subjectDn, issuerDn, fingerprint);
                writeErrorResponse(response);
                return;
            }
            passedChecks.add("allowedFingerprints");
        }

        // Safety guard — reject if no authorization check was actually evaluated
        if (passedChecks.isEmpty()) {
            logger.error("Management mTLS authorization REJECTED — "
                            + "no authorization checks were configured. "
                            + "Subject: [{}], Issuer: [{}], Fingerprint: [{}]",
                    subjectDn, issuerDn, fingerprint);
            writeErrorResponse(response);
            return;
        }

        logger.info("Management mTLS authorization ACCEPTED (passed checks: {}). "
                        + "Subject: [{}], Issuer: [{}], Fingerprint: [{}]",
                String.join(", ", passedChecks), subjectDn, issuerDn, fingerprint);

        filterChain.doFilter(request, response);
    }

    private boolean validateCertChain(X509Certificate[] certs) {
        // Perform PKIX chain validation using the configured trust anchors. Tomcat/reverse proxy has already performed
        // its own PKIX validation during the TLS handshake, making sure the certificate is valid (not expired) and
        // chains up to a trusted CA in the server's main truststore. However, this allows additional narrowing
        // of trust by validating the cert chain against a separate set of trust anchors specific to certificate management.
        // This ensures not all certificates accepted by Tomcat (when mTLS is enabled for all endpoints) are necessarily
        // authorized for credential management operations.
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // PKIX requires the CertPath to exclude the trust anchor itself —
            // only certificates below the anchor should be included.
            List<X509Certificate> chainWithoutAnchors = Arrays.stream(certs)
                    .takeWhile(cert -> trustAnchors.stream()
                            .noneMatch(anchor -> anchor.getTrustedCert().equals(cert)))
                    .toList();
            CertPath certPath = cf.generateCertPath(chainWithoutAnchors);
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false); // Tomcat or reverse proxy should have already performed a revocation check during TLS handshake if configured.

            PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer(certPath, params);

            if (reviewer.isValidCertPath()) {
                for (int i = 0; i < reviewer.getCertPathSize(); i++) {
                    for (Object notification : reviewer.getNotifications(i)) {
                        ErrorBundle bundle = (ErrorBundle) notification;
                        logger.debug("PKIX chain validation notification at cert [{}]: {}", i, bundle.getText(Locale.ENGLISH));
                    }
                }
                return true;
            }

            for (int i = 0; i < reviewer.getCertPathSize(); i++) {
                for (Object error : reviewer.getErrors(i)) {
                    ErrorBundle bundle = (ErrorBundle) error;
                    logger.warn("PKIX chain validation error at cert [{}]: {}", i, bundle.getText(Locale.ENGLISH));
                }
            }
            return false;
        } catch (CertPathReviewerException e) {
            logger.warn("PKIX chain validation could not be performed: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.warn("PKIX chain validation failed: {}", e.getMessage());
            return false;
        }
    }

    private void writeErrorResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(),
                new ErrorDto("forbidden",
                        "Client certificate is not authorized for credential management."));
    }

}
