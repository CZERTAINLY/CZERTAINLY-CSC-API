package com.czertainly.csc.crypto;

import com.czertainly.csc.utils.cert.CertificateUtils;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class FingerprintUtilsTest {

    @Test
    void shouldComputeCorrectSha256Fingerprint() {
        // GIVEN
        X509Certificate testCert = CertificateUtils.generateSelfSignedCertificate(
                "CN=Test User,O=Test Org"
        );

        // WHEN
        String fingerprint = FingerprintUtils.computeSha256Fingerprint(testCert);

        // THEN
        assertThat(fingerprint).isNotNull();
        assertThat(fingerprint).matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");  // SHA-256 is 32 bytes = 64 hex chars with colons
    }

    @Test
    void shouldNormalizeFingerprintFormats() {
        // GIVEN
        String colonSeparated = "A1:B2:C3:D4";
        String noColons = "A1B2C3D4";
        String withSpaces = "A1 B2 C3 D4";
        String lowercase = "a1:b2:c3:d4";

        // WHEN
        String normalized1 = FingerprintUtils.normalizeFingerprint(colonSeparated);
        String normalized2 = FingerprintUtils.normalizeFingerprint(noColons);
        String normalized3 = FingerprintUtils.normalizeFingerprint(withSpaces);
        String normalized4 = FingerprintUtils.normalizeFingerprint(lowercase);

        // THEN - all should produce the same normalized uppercase colon-separated format
        assertThat(normalized1).isEqualTo("A1:B2:C3:D4");
        assertThat(normalized2).isEqualTo("A1:B2:C3:D4");
        assertThat(normalized3).isEqualTo("A1:B2:C3:D4");
        assertThat(normalized4).isEqualTo("A1:B2:C3:D4");
    }
}
