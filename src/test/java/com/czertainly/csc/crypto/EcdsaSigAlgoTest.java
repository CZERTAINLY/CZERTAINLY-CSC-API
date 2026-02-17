package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EcdsaSigAlgoTest {

    private final AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    @Test
    void shouldReturnEcdsaAsEncryptionAlgorithm() {
        // GIVEN / WHEN
        EcdsaSigAlgo algo = EcdsaSigAlgo.of(X9ObjectIdentifiers.ecdsa_with_SHA256, NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("ECDSA", algo.encryptionAlgorithm());
    }

    @Test
    void shouldReturnDigestAlgorithmName() {
        // GIVEN / WHEN
        EcdsaSigAlgo algo = EcdsaSigAlgo.of(X9ObjectIdentifiers.ecdsa_with_SHA256, NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("SHA256", algo.digestAlgorithm());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha256() {
        // GIVEN / WHEN
        EcdsaSigAlgo algo = EcdsaSigAlgo.of(X9ObjectIdentifiers.ecdsa_with_SHA256, NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("SHA256WithECDSA", algo.toJavaName());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha384() {
        // GIVEN / WHEN
        EcdsaSigAlgo algo = EcdsaSigAlgo.of(X9ObjectIdentifiers.ecdsa_with_SHA384, NISTObjectIdentifiers.id_sha384, algorithmHelper);

        // THEN
        assertEquals("SHA384WithECDSA", algo.toJavaName());
    }
}
