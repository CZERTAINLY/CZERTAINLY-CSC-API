package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.api.common.ErrorDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


/**
 * Servlet filter that resolves the client certificate from either the TLS handshake or a configurable
 * HTTP header (for reverse proxy scenarios). When {@code fallbackToOAuth2} is {@code true}, the filter
 * continues the chain without a certificate so that downstream OAuth2 processing can authenticate the
 * request. When {@code false}, the filter returns 401 Unauthorized if no certificate is found.
 */
public class MtlsClientCertificateFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(MtlsClientCertificateFilter.class);
    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";


    private final ObjectMapper objectMapper;
    private final boolean fallbackToOAuth2Enabled;
    private final String clientCertificateHeader;

    public MtlsClientCertificateFilter(ObjectMapper objectMapper, boolean fallbackToOAuth2Enabled, String clientCertificateHeader) {
        this.objectMapper = objectMapper;
        this.fallbackToOAuth2Enabled = fallbackToOAuth2Enabled;
        this.clientCertificateHeader = clientCertificateHeader;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);

        if (certs != null && certs.length > 0) {
            if (!isEndEntity(certs[0])) {
                logger.warn("Certificate(s) found in TLS handshake but the first certificate does not appear to be an end-entity certificate. " +
                        "Subject of first certificate: [{}], remote address: {}. The request will be rejected.",
                        certs[0].getSubjectX500Principal().getName(), request.getRemoteAddr());
                writeErrorResponse(response);
                return;
            }
            logger.trace("Client certificate presented in TLS handshake, subject: [{}], remote address: {}",
                    certs[0].getSubjectX500Principal().getName(), request.getRemoteAddr());
        } else {
            // No cert from TLS handshake, try to extract from the header
            X509Certificate[] headerCerts = extractCertificatesFromHeader(request);
            if (headerCerts != null) {
                certs = headerCerts;
                request.setAttribute(CERT_ATTRIBUTE, certs);
                logger.trace("Certificate(s) extracted from header '{}', Subject: [{}], remote address: {}",
                        clientCertificateHeader, certs[0].getSubjectX500Principal().getName(), request.getRemoteAddr());
            } else {
                // No certificate found in the header either, check if we should fall back to OAuth2 or reject the request
                if (fallbackToOAuth2Enabled) {
                    logger.debug("No client certificate presented, falling back to OAuth2 authentication. "
                            + "Remote address: {}", request.getRemoteAddr());
                } else {
                    logger.info("Management API request rejected: no client certificate presented. "
                            + "Remote address: {}", request.getRemoteAddr());
                    writeErrorResponse(response);
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private X509Certificate[] extractCertificatesFromHeader(HttpServletRequest request) {
        if (clientCertificateHeader == null || clientCertificateHeader.isBlank()) {
            logger.debug("The name of the header to extract client certificate from is not configured. Skipping header extraction.");
            return null;
        }

        String headerValue = request.getHeader(clientCertificateHeader);
        if (headerValue == null || headerValue.isBlank()) {
            logger.debug("Client certificate header '{}' is not present or empty in the request.", clientCertificateHeader);
            return null;
        }

        try {
            String trimmed = headerValue.trim();
            logger.trace("Raw client certificate header value length: {} chars", trimmed.length());

            // URL-decode if the value appears to be URL-encoded (e.g. contains % characters)
            String decoded = trimmed.contains("%") ? URLDecoder.decode(trimmed, StandardCharsets.UTF_8) : trimmed;

            ArrayList<X509Certificate> certList = parsePemCertificates(decoded);

            if (!certList.isEmpty()) {
                certList = ensureEndEntityFirst(certList);
                validateExpiration(certList);

                X509Certificate[] result = certList.toArray(X509Certificate[]::new);
                logger.debug("Extracted {} certificate(s) from header '{}', end-entity subject: [{}]",
                        result.length, clientCertificateHeader, result[0].getSubjectX500Principal().getName());
                return result;
            } else {
                // if PEM parsing found nothing, as a last resort, try parsing as raw Base64-encoded DER
                X509Certificate derCert = parseBase64Der(decoded);
                if (derCert != null) {
                    validateExpiration(List.of(derCert));
                    logger.debug("Parsed certificate from header '{}' as raw Base64-encoded DER, subject: [{}]",
                            clientCertificateHeader, derCert.getSubjectX500Principal().getName());
                    return new X509Certificate[]{derCert};
                }
                logger.debug("No certificates found in header '{}'", clientCertificateHeader);
                return null;
            }
        } catch (Exception e) {
            logger.debug("Failed to use client certificate from header '{}'",
                    clientCertificateHeader, e);
            return null;
        }
    }

    /**
     * Parses PEM-encoded certificates from the given string using BouncyCastle's {@link PEMParser}.
     * Returns an empty list if the input contains no PEM certificate blocks.
     */
    private static ArrayList<X509Certificate> parsePemCertificates(String pem) throws Exception {
        ArrayList<X509Certificate> certList = new ArrayList<>();
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            Object obj;
            while ((obj = pemParser.readObject()) != null) {
                if (obj instanceof X509CertificateHolder holder) {
                    certList.add(new JcaX509CertificateConverter().getCertificate(holder));
                }
            }
        }
        return certList;
    }

    /**
     * Ensures the end-entity certificate is first in the list. Checks if the first certificate
     * is an end-entity (not a CA). If not, reverses the list and checks again. Throws if neither
     * order places the end-entity first.
     *
     * @return the list with the end-entity certificate first
     */
    private ArrayList<X509Certificate> ensureEndEntityFirst(ArrayList<X509Certificate> certs) {
        if (isEndEntity(certs.getFirst())) {
            return certs;
        }

        // Try reversed order (end-entity might be last)
        ArrayList<X509Certificate> reversed = new ArrayList<>(certs);
        Collections.reverse(reversed);

        if (isEndEntity(reversed.getFirst())) {
            logger.debug("Certificate chain from header '{}' was in reverse order (CA first), reversed to end-entity first.",
                    clientCertificateHeader);
            return reversed;
        }

        throw new IllegalArgumentException(
                "Certificate chain in header '%s' must be ordered with the end-entity certificate first or last. "
                        .formatted(clientCertificateHeader)
                + "Neither the first nor the last certificate appears to be an end-entity (non-CA) certificate.");
    }

    /**
     * Attempts to parse a raw Base64-encoded DER certificate (without PEM headers).
     * Returns null if the input is not valid Base64 or not a valid X.509 certificate.
     */
    private static X509Certificate parseBase64Der(String value) {
        try {
            String stripped = value.replaceAll("\\s+", "");
            byte[] derBytes = java.util.Base64.getDecoder().decode(stripped);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
        } catch (Exception e) {
            logger.debug("Failed to parse certificate as Base64-encoded DER (length: {} chars).", value.length(), e);
            return null;
        }
    }

    private static void validateExpiration(List<X509Certificate> certs)
            throws CertificateExpiredException, CertificateNotYetValidException {
        for (X509Certificate cert : certs) {
            cert.checkValidity();
        }
    }

    private static boolean isEndEntity(X509Certificate cert) {
        // getBasicConstraints() returns -1 if the extension is absent or CA=false (end-entity),
        // and >= 0 if CA=true (the value is the pathLenConstraint, or Integer.MAX_VALUE if unconstrained)
        return cert.getBasicConstraints() < 0;
    }

    private void writeErrorResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(),
                new ErrorDto("unauthorized", "Client certificate is required."));
    }
}
