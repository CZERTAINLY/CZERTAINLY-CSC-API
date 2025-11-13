package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AlgorithmUnifierTest {

    @Mock
    private AlgorithmHelper algorithmHelper;

    @InjectMocks
    private AlgorithmUnifier algorithmUnifier;

    @Test
    void unifyWithSignatureAlgorithm() {
        // given
        String signAlgo = "SHA256WITHECDSA";
        String hashAlgorithmOID = null;
        when(algorithmHelper.isSignatureAlgorithm(signAlgo)).thenReturn(true);
        when(algorithmHelper.getSignatureAlgorithmName(signAlgo)).thenReturn(signAlgo);

        // when
        Result<AlgorithmPair, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgo, hashAlgorithmOID);

        // then
        assertNotNull(result.unwrap());
        assertEquals("SHA256", result.unwrap().digestAlgo());
        assertEquals("ECDSA", result.unwrap().keyAlgo());
    }

    @Test
    void unifyWithKeyAlgorithm() {
        // given
        String hashAlgorithmOID = "2.16.840.1.101.3.4.2.1"; // SHA-256
        String keyAlgo = "AES";
        when(algorithmHelper.isKeyAlgorithm(keyAlgo)).thenReturn(true);
        when(algorithmHelper.getDigestAlgorithmName(hashAlgorithmOID)).thenReturn("SHA-256");
        when(algorithmHelper.getAlgorithmName(keyAlgo)).thenReturn("AES");

        // when
        Result<AlgorithmPair, AlgorithmUnificationError> result = algorithmUnifier.unify(keyAlgo, hashAlgorithmOID);

        // then
        assertNotNull(result.unwrap());
        assertEquals("SHA-256", result.unwrap().digestAlgo());
        assertEquals("AES", result.unwrap().keyAlgo());
    }

    @Test
    void unifyWithMissingDigestAlgorithm() {
        // given
        String hashAlgorithmOID = null;
        String keyAlgo = "AES";
        when(algorithmHelper.isKeyAlgorithm(keyAlgo)).thenReturn(true);
        when(algorithmHelper.getDigestAlgorithmName(hashAlgorithmOID)).thenReturn(null);

        // when
        Result<AlgorithmPair, AlgorithmUnificationError> result = algorithmUnifier.unify(keyAlgo, hashAlgorithmOID);

        // then
        assertNotNull(result.unwrapError());
        assertInstanceOf(AlgorithmUnificationError.DigestAlgorithmMissing.class, result.unwrapError());
    }

    @Test
    void unifyWithIncompatibleAlgorithms() {
        // given
        String signAlgo = "SHA256WITHECDSA";
        String hashAlgorithmOID = "1.2.840.113549.2.5";
        when(algorithmHelper.isSignatureAlgorithm(signAlgo)).thenReturn(true);
        when(algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(hashAlgorithmOID, signAlgo)).thenReturn(
                false);

        // when
        Result<AlgorithmPair, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgo, hashAlgorithmOID);

        // then
        assertNotNull(result.unwrapError());
        assertInstanceOf(AlgorithmUnificationError.IncompatibleAlgorithms.class, result.unwrapError());
    }

    @Test
    void unifyWithUnknownSignature() {
        // given
        String signAlgo = "UNKNOWN_ALGO";
        when(algorithmHelper.isSignatureAlgorithm(signAlgo)).thenReturn(false);

        // when
        Result<AlgorithmPair, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgo, null);

        // then
        assertNotNull(result.unwrapError());
        assertInstanceOf(AlgorithmUnificationError.SignatureAlgorithmMissing.class, result.unwrapError());
    }

    @Test
    void unifyWithIllegalArgumentException() {
        // given
        String signAlgo = "SHA256WITHECDSA";
        when(algorithmHelper.isSignatureAlgorithm(signAlgo)).thenThrow(
                new IllegalArgumentException("Invalid argument"));

        // when
        Result<AlgorithmPair, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgo, null);

        // then
        assertNotNull(result.unwrapError());
        assertInstanceOf(AlgorithmUnificationError.OtherError.class, result.unwrapError());
    }
}
