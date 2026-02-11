package com.czertainly.csc.crypto;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.utils.cert.CertificateUtils;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
        assertThat(fingerprint)
                .isNotNull()
                .matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");  // SHA-256 is 32 bytes = 64 hex chars with colons
    }

    @Test
    void shouldNormalizeFingerprintFormats() {
        // GIVEN
        String colonSeparated = "A1:B2:C3:D4";
        String noColons = "A1B2C3D4";
        String withSpaces = "A1 B2 C3 D4";
        String lowercase = "a1:b2:c3:d4";

        // WHEN & THEN — all formats should produce the same normalized uppercase colon-separated format
        assertThat(FingerprintUtils.normalizeFingerprint(colonSeparated, 4)).isEqualTo("A1:B2:C3:D4");
        assertThat(FingerprintUtils.normalizeFingerprint(noColons, 4)).isEqualTo("A1:B2:C3:D4");
        assertThat(FingerprintUtils.normalizeFingerprint(withSpaces, 4)).isEqualTo("A1:B2:C3:D4");
        assertThat(FingerprintUtils.normalizeFingerprint(lowercase, 4)).isEqualTo("A1:B2:C3:D4");
    }

    @Test
    void shouldRejectFingerprintWithWrongLength() {
        // GIVEN — valid hex but wrong length for expected 4 bytes
        String tooShort = "A1B2";

        // WHEN & THEN
        assertThatThrownBy(() -> FingerprintUtils.normalizeFingerprint(tooShort, 4))
                .isInstanceOf(ApplicationConfigurationException.class)
                .hasMessageContaining("Expected 4 bytes but got 2 bytes");
    }

    @Test
    void shouldRejectFingerprintWithInvalidHexCharacters() {
        // GIVEN — contains non-hex characters
        String invalidHex = "ZZZZ1234";

        // WHEN & THEN
        assertThatThrownBy(() -> FingerprintUtils.normalizeFingerprint(invalidHex, 4))
                .isInstanceOf(ApplicationConfigurationException.class)
                .hasMessageContaining("Fingerprint must be 8 hexadecimal characters")
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }
}
