package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyAndHashSigAlgoTest {

    private final AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    @Test
    void shouldReturnRsaAsEncryptionAlgorithm() {
        // GIVEN / WHEN
        KeyAndHashSigAlgo algo = KeyAndHashSigAlgo.of(
                PKCSObjectIdentifiers.rsaEncryption, NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("RSA", algo.encryptionAlgorithm());
    }

    @Test
    void shouldReturnDigestAlgorithmName() {
        // GIVEN / WHEN
        KeyAndHashSigAlgo algo = KeyAndHashSigAlgo.of(
                PKCSObjectIdentifiers.rsaEncryption, NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("SHA256", algo.digestAlgorithm());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha256WithRsa() {
        // GIVEN / WHEN
        KeyAndHashSigAlgo algo = KeyAndHashSigAlgo.of(
                PKCSObjectIdentifiers.rsaEncryption, NISTObjectIdentifiers.id_sha256, algorithmHelper);

        // THEN
        assertEquals("SHA256WithRSA", algo.toJavaName());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha384WithRsa() {
        // GIVEN / WHEN
        KeyAndHashSigAlgo algo = KeyAndHashSigAlgo.of(
                PKCSObjectIdentifiers.rsaEncryption, NISTObjectIdentifiers.id_sha384, algorithmHelper);

        // THEN
        assertEquals("SHA384WithRSA", algo.toJavaName());
    }

    @Test
    void shouldReturnCorrectJavaNameForSha512WithRsa() {
        // GIVEN / WHEN
        KeyAndHashSigAlgo algo = KeyAndHashSigAlgo.of(
                PKCSObjectIdentifiers.rsaEncryption, NISTObjectIdentifiers.id_sha512, algorithmHelper);

        // THEN
        assertEquals("SHA512WithRSA", algo.toJavaName());
    }
}
