package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PureSignatureAlgoTest {

    private final AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    @Test
    void shouldReturnAlgorithmNameAsEncryptionAlgorithm() {
        // GIVEN / WHEN
        PureSignatureAlgo algo = PureSignatureAlgo.of(EdECObjectIdentifiers.id_Ed25519, algorithmHelper);

        // THEN
        assertEquals("ED25519", algo.encryptionAlgorithm());
    }

    @Test
    void shouldReturnNullDigestAlgorithm() {
        // GIVEN / WHEN
        PureSignatureAlgo algo = PureSignatureAlgo.of(EdECObjectIdentifiers.id_Ed25519, algorithmHelper);

        // THEN
        assertNull(algo.digestAlgorithm());
    }

    @Test
    void shouldReturnAlgorithmNameAsJavaName() {
        // GIVEN / WHEN
        PureSignatureAlgo algo = PureSignatureAlgo.of(EdECObjectIdentifiers.id_Ed448, algorithmHelper);

        // THEN
        assertEquals("ED448", algo.toJavaName());
    }
}
