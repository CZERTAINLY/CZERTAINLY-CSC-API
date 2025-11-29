package com.czertainly.csc.signing.signatureauthorizers;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HashAuthorizerTest {

    private HashAuthorizer authorizer;
    private SignatureActivationData sad;

    @BeforeEach
    void setUp() {
        authorizer = new HashAuthorizer();
        sad = mock(SignatureActivationData.class);
    }

    @Test
    void authorizeWhenSadHasNoHashesReturnsFalse() {
        //given
        when(sad.getHashes()).thenReturn(Optional.empty());

        // when
        Result<Boolean, TextError> result = authorizer.authorize(List.of("hash1", "hash2"), sad);

        // then
        assertFalse(result.unwrap());
    }

    @Test
    void authorizeWhenHashesDoNotMatchReturnsFalse() {
        // given
        when(sad.getHashes()).thenReturn(Optional.of(Set.of("hash1", "hash2")));

        // when
        Result<Boolean, TextError> result = authorizer.authorize(List.of("hash3"), sad);

        // then
        assertFalse(result.unwrap());
    }

    @Test
    void authorizeWhenNumSignaturesLessThanDocumentHashesReturnsFalse() {
        // given
        when(sad.getHashes()).thenReturn(Optional.of(Set.of("hash1", "hash2")));
        when(sad.getNumSignatures()).thenReturn(1);

        // when
        Result<Boolean, TextError> result = authorizer.authorize(List.of("hash1", "hash2"), sad);

        // then
        assertFalse(result.unwrap());
    }

    @Test
    void authorizeWhenValidReturnsTrue() {
        // given
        when(sad.getHashes()).thenReturn(Optional.of(Set.of("hash1", "hash2")));
        when(sad.getNumSignatures()).thenReturn(2);

        // when
        Result<Boolean, TextError> result = authorizer.authorize(List.of("hash1", "hash2"), sad);

        // then
        assertTrue(result.unwrap());
    }
}
