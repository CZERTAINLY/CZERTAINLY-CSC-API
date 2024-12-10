package com.czertainly.csc.api.auth;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.PublicJwk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class JwksParser {

    private final Logger logger = LoggerFactory.getLogger(JwksParser.class);

    private final Parser<JwkSet> parser;

    public JwksParser() {
        this.parser = Jwks.setParser().build();
    }

    public Result<Set<PublicJwk<?>>, TextError> parse(String jwksString) {
        try {
            JwkSet set = parser.parse(jwksString);
            Set<PublicJwk<?>> publicJwks = new HashSet<>();
            for (Jwk<?> jwk : set.getKeys()) {
                if (jwk instanceof PublicJwk<?>) {
                    publicJwks.add((PublicJwk<?>) jwk);
                }
            }
            return Result.success(publicJwks);
        } catch (Exception e) {
            logger.error("Failed to parse JWKS.", e);
            return Result.error(new TextError("Failed to parse JWKS."));
        }
    }
}
