package com.czertainly.csc.api.auth;

import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.utils.jwt.TestJwtBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SADParserTest {

    @Mock
    private TokenValidator mockValidator;

    @InjectMocks
    private SADParser sadParser;

    @Test
    void parseValidSAD() {
        // given
        String sad = aSAD();
        Jws<Claims> mockJws = aJws(
                "userId123",
                "credentialId456",
                "qualifier789",
                "hashAlgoOID",
                2,
                Set.of("hash1", "hash2")
        );
        when(mockValidator.validate(sad)).thenReturn(Result.success(mockJws));

        // when
        SignatureActivationData result = sadParser.parse(sad);

        // then
        assertNotNull(result);
        assertEquals("userId123", result.getUserID().orElse(null));
        assertEquals("credentialId456", result.getCredentialID().orElse(null));
        assertEquals("qualifier789", result.getSignatureQualifier().orElse(null));
        assertEquals(2, result.getNumSignatures());
        assertTrue(result.getHashes().orElse(Set.of()).contains("hash1"));
        assertTrue(result.getHashes().orElse(Set.of()).contains("hash2"));
    }

    @Test
    void parseInvalidSADThrowsException() {
        // given
        String sad = "invalidSadToken";
        when(mockValidator.validate(sad)).thenReturn(Result.error(TextError.of("Validation error")));

        // when
        Executable cb = () -> sadParser.parse(sad);

        // then
        InvalidInputDataException exception = assertThrows(InvalidInputDataException.class, cb);
        assertEquals("Failed to validate SAD: Validation error", exception.getMessage());
    }

    private String aSAD() {
        return new TestJwtBuilder()
                .withUserID("userId123")
                .withCredentialID("credentialId456")
                .withSignatureQualifier("qualifier789")
                .withNumOfSignatures("2")
                .withHashAlgorithmOID("hashAlgoOID")
                .withHashes(Set.of("hash1", "hash2"))
                .build()
                .getTokenValue();
    }

    private Jws<Claims> aJws(String userID, String credentialID, String signatureQualifier,
                             String hashAlgorithmOID, int numSignatures, Set<String> hashes) {

        Claims claims = Mockito.mock(Claims.class);
        when(claims.get("userID", String.class)).thenReturn(userID);
        when(claims.get("credentialID", String.class)).thenReturn(credentialID);
        when(claims.get("signatureQualifier", String.class)).thenReturn(signatureQualifier);
        when(claims.get("hashAlgorithmOID", String.class)).thenReturn(hashAlgorithmOID);
        when(claims.get("numSignatures", String.class)).thenReturn(String.valueOf(numSignatures));
        when(claims.get("hashes")).thenReturn(List.copyOf(hashes));

        Jws<Claims> jwt = mock(Jws.class);
        when(jwt.getPayload()).thenReturn(claims);

        return jwt;
    }
}
