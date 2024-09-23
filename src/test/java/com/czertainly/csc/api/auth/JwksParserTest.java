package com.czertainly.csc.api.auth;

import org.junit.jupiter.api.Test;

import static com.czertainly.csc.utils.jwt.Constants.JWKS_STRING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JwksParserTest {

    JwksParser jwksParser = new JwksParser();

    @Test
    void canParseJwks() {
        // given
        String jwks = JWKS_STRING;

        // when
        var result = jwksParser.parse(jwks);

        // then
        assertEquals(2, result.size());
        result.forEach(jwk -> {
            assertNotNull(jwk.getId());
            assertNotNull(jwk.getAlgorithm());
            assertNotNull(jwk.getPublicKeyUse());
            assertNotNull(jwk.getX509Chain());
        });

    }
}