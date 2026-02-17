package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PssSignatureAlgoTest {

    private final AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    @Test
    void shouldReturnRsassaPssAsEncryptionAlgorithm() {
        // GIVEN / WHEN
        PssSignatureAlgo algo = PssSignatureAlgo.of(NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("RSASSA-PSS", algo.encryptionAlgorithm());
    }

    @Test
    void shouldReturnDigestAlgorithmName() {
        // GIVEN / WHEN
        PssSignatureAlgo algo = PssSignatureAlgo.of(NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("SHA256", algo.digestAlgorithm());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha256() {
        // GIVEN / WHEN
        PssSignatureAlgo algo = PssSignatureAlgo.of(NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("SHA256withRSAandMGF1", algo.toJavaName());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha384() {
        // GIVEN / WHEN
        PssSignatureAlgo algo = PssSignatureAlgo.of(NISTObjectIdentifiers.id_sha384, algorithmHelper);

        // THEN
        assertEquals("SHA384withRSAandMGF1", algo.toJavaName());
    }
}
