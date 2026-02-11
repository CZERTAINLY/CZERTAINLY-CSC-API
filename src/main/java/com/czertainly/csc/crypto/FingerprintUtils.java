package com.czertainly.csc.crypto;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

public final class FingerprintUtils {

    // for output formatting with colons and uppercase
    private static final HexFormat COLON_SEPARATED_HEX = HexFormat.ofDelimiter(":").withUpperCase();
    // plain hex for parsing input without delimiters
    private static final HexFormat PLAIN_HEX = HexFormat.of();

    private FingerprintUtils() { }

    /**
     * Computes the SHA-256 fingerprint of an X.509 certificate.
     *
     * @param cert the certificate to compute the fingerprint for
     * @return the fingerprint in uppercase colon-separated hex format
     */
    public static String computeSha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return formatFingerprint(digest);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Failed to compute certificate fingerprint", e);
        }
    }

    /**
     * Formats a raw byte digest as an uppercase colon-separated hex string.
     *
     * @param digest the raw bytes to format
     * @return the formatted fingerprint (e.g. {@code A1:B2:C3:D4})
     */
    public static String formatFingerprint(byte[] digest) {
        return COLON_SEPARATED_HEX.formatHex(digest);
    }


    /**
     * Normalizes a certificate fingerprint to uppercase colon-separated hex format.
     * Accepts flexible input formats: plain hex, colon-separated, space-separated, and mixed case.
     *
     * @param fingerprint   the fingerprint string to normalize
     * @param expectedBytes the expected number of bytes (e.g. 32 for SHA-256)
     * @return the normalized fingerprint in uppercase colon-separated format (e.g. {@code A1:B2:C3:D4})
     * @throws ApplicationConfigurationException if the fingerprint contains invalid hex characters
     *                                           or does not match the expected byte length
     */
    public static String normalizeFingerprint(String fingerprint, int expectedBytes) {
        // Strip colons, spaces; allows flexible input formats
        String sanitizedFingerprint = fingerprint.replaceAll("[:\\s]", "");
        try {
            byte[] bytes = PLAIN_HEX.parseHex(sanitizedFingerprint);
            if (bytes.length != expectedBytes) {
                throw new ApplicationConfigurationException(
                        "Invalid certificate fingerprint '%s'. Expected %d bytes but got %d bytes."
                                .formatted(fingerprint, expectedBytes, bytes.length));
            }
            return formatFingerprint(bytes);
        } catch (IllegalArgumentException e) {
            throw new ApplicationConfigurationException(
                    "Invalid certificate fingerprint '%s'. Fingerprint must be %d hexadecimal characters, optionally separated by colons or spaces."
                            .formatted(fingerprint, expectedBytes * 2),
                    e
            );
        }
    }
}
