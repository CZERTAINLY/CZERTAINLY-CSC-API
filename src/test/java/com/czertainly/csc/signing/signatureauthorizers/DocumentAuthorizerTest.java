package com.czertainly.csc.signing.signatureauthorizers;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.AlgorithmHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DocumentAuthorizerTest {

    @Mock
    private AlgorithmHelper algorithmHelper;

    @Spy
    private DocumentHashAuthorizer documentHashAuthorizer = new DocumentHashAuthorizer();

    @InjectMocks
    private DocumentAuthorizer documentAuthorizer;

    @Mock
    private SignatureActivationData sad;

    @Test
    void authorizeSuccess() {
        // given
        String oid = "1.2.840.113549.2.5"; // MD5
        when(sad.getHashAlgorithmOID()).thenReturn(Optional.of(oid));
        when(sad.getHashes()).thenReturn(Optional.of(Set.of("g+SxeJMG09HJkUDfOCfWAA==", "JxVZ7CUmi7m7Ktf9i0z3Gg==")));
        when(sad.getNumSignatures()).thenReturn(2);
        when(algorithmHelper.getDigestAlgorithmName(oid)).thenReturn("MD5");
        List<String> documents = Arrays.asList("doc1", "doc2");

        // when
        Result<Boolean, TextError> result = documentAuthorizer.authorize(documents, sad);

        // then
        assertTrue(result.unwrap());
        verify(documentHashAuthorizer).authorize(any(), eq(sad));
    }

    @Test
    void authorizeNoHashAlgorithmOID() {
        // given
        when(sad.getHashAlgorithmOID()).thenReturn(Optional.empty());

        // when
        Result<Boolean, TextError> result = documentAuthorizer.authorize(Collections.emptyList(), sad);

        // then
        assertEquals("No hash algorithm OID provided in the signature activation data.", result.unwrapError().getErrorText());
    }

    @Test
    void authorizeUnknownDigestAlgorithm() {
        // given
        String oid = "1.2.3.4.5.6";
        when(sad.getHashAlgorithmOID()).thenReturn(Optional.of(oid));
        when(algorithmHelper.getDigestAlgorithmName(oid)).thenReturn(null);

        // when
        Result<Boolean, TextError> result = documentAuthorizer.authorize(Collections.emptyList(), sad);

        // then
        assertEquals("Unknown digest algorithm OID: " + oid, result.unwrapError().getErrorText());
    }

    @Test
    void authorizeMessageDigestCreationFailure() {
        // given
        String oid = "1.2.3.4.5.6";
        when(sad.getHashAlgorithmOID()).thenReturn(Optional.of(oid));
        when(algorithmHelper.getDigestAlgorithmName(oid)).thenReturn("FOOBAR");
        List<String> documents = Arrays.asList("doc1", "doc2");

        // when
        Result<Boolean, TextError> result = documentAuthorizer.authorize(documents, sad);

        // then
        assertTrue(result.unwrapError().getErrorText().contains("Unable to obtain instance of Message Digest"));
    }
}
