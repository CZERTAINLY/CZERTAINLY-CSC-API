package com.czertainly.csc.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;

public final class FingerprintUtils {

    // for output formatting with colons and uppercase
    private static final HexFormat COLON_SEPARATED_HEX = HexFormat.ofDelimiter(":").withUpperCase();
    // plain hex for parsing input without delimiters
    private static final HexFormat PLAIN_HEX = HexFormat.of();

    private FingerprintUtils() {
    }

    public static String computeSha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return formatFingerprint(digest);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Failed to compute certificate fingerprint", e);
        }
    }

    public static String formatFingerprint(byte[] digest) {
        return COLON_SEPARATED_HEX.formatHex(digest);
    }

    public static List<String> normalizeFingerprints(List<String> fingerprints) {
        if (fingerprints == null || fingerprints.isEmpty()) {
            return List.of();
        }
        return fingerprints.stream()
                .map(FingerprintUtils::normalizeFingerprint)
                .toList();
    }

    public static String normalizeFingerprint(String fingerprint) {
        // Strip colons, spaces; uppercase — allows flexible input formats
        String sanitizedFingerprint = fingerprint.replaceAll("[:\\s]", "");
        byte[] bytes = PLAIN_HEX.parseHex(sanitizedFingerprint);

        return formatFingerprint(bytes);
    }
}
