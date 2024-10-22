package com.czertainly.csc.api.auth;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Success;
import com.czertainly.csc.utils.jwt.TestJWTs;
import com.czertainly.csc.utils.jwt.TestJwkGenerator;
import com.czertainly.csc.utils.jwt.TestJwtBuilder;
import com.czertainly.csc.utils.jwt.TestKeyLocator;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static com.czertainly.csc.utils.jwt.Constants.TEST_AUDIENCE;
import static com.czertainly.csc.utils.jwt.Constants.TEST_ISSUER;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenValidatorTest {

    TestJwtBuilder jwtBuilder = new TestJwtBuilder();

    TestKeyLocator keyLocator = new TestKeyLocator(TestJwkGenerator.defaultJwkSet);
    TokenValidator validator = new TokenValidator(keyLocator, TEST_ISSUER, TEST_AUDIENCE, 1);

    @Test
    public void succeedsWithValidToken() {
        // given
        var jwt = TestJWTs.serviceToken(
                Map.of("sub", "test-subject",
                       "aud", TEST_AUDIENCE,
                       "iss", TEST_ISSUER
                )
        );

        // when
        var result = validator.validate(jwt.getTokenValue());

        // then
        assertInstanceOf(Success.class, result);
    }

    @Test
    public void failsWithInvalidAudience() {
        // given
        var jwt = TestJWTs.serviceToken(
                Map.of("sub", "test-subject",
                       "aud", "invalid-audience",
                       "iss", TEST_ISSUER
                )
        );

        // when
        var result = validator.validate(jwt.getTokenValue());

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getError().contains("aud"));
    }

    @Test
    public void failsWithInvalidIssuer() {
        // given
        var jwt = TestJWTs.serviceToken(
                Map.of("sub", "test-subject",
                       "aud", TEST_AUDIENCE,
                       "iss", "invalid-issuer"
                )
        );

        // when
        var result = validator.validate(jwt.getTokenValue());

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText().contains("iss"));
    }

    @Test
    public void failsWithExpiredToken() {
        // given
        var jwt = jwtBuilder.withClaims(validClaims())
                            .withIssuedAt(Instant.now().minus(Duration.ofHours(2)))
                            .withExpiration(Instant.now().minus(Duration.ofHours(1)))
                            .build();

        // when
        var result = validator.validate(jwt.getTokenValue());

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText().contains("expired"));

    }

    @Test
    public void failsWithNotYetValidToken() {
        // given
        var jwt = jwtBuilder.withClaims(validClaims())
                            .withIssuedAt(Instant.now().plus(Duration.ofHours(1)))
                            .withExpiration(Instant.now().plus(Duration.ofHours(2)))
                            .build();

        // when
        var result = validator.validate(jwt.getTokenValue());

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText().contains("issued at future"));
    }

    @Test
    public void failsWithTokenSignedByUnknownKey() {
        // given
        JWK maliciousKey = TestJwkGenerator.generate("RSA", UUID.randomUUID().toString());
        var maliciousBuilder = new TestJwtBuilder(TestJwkGenerator.getJwkSource(maliciousKey));
        var maliciousJwt = maliciousBuilder.withClaims(validClaims())
                                           .build();

        // when
        var result = validator.validate(maliciousJwt.getTokenValue());

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText().contains("Failed to locate key"));
    }

    @Test
    public void failsWithTokenWithFraudulentKey() {
        // given
        JWK maliciousKey = TestJwkGenerator.generate("RSA", TestJwkGenerator.defaultKeyId);
        var maliciousBuilder = new TestJwtBuilder(TestJwkGenerator.getJwkSource(maliciousKey));
        var maliciousJwt = maliciousBuilder.withClaims(validClaims())
                                           .build();

        // when
        var result = validator.validate(maliciousJwt.getTokenValue());

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText().contains("signature does not match"));
    }

    public Map<String, String> validClaims() {
        return Map.of("sub", "test-subject",
                      "aud", TEST_AUDIENCE,
                      "iss", TEST_ISSUER
        );
    }

}