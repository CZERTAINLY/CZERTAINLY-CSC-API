package com.czertainly.csc.api.auth;

import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.PublicJwk;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class JwksParser {

    private final Parser<JwkSet> parser;

    public JwksParser() {
        this.parser = Jwks.setParser().build();
    }

    public Set<PublicJwk<?>> parse(String jwksString) {
        JwkSet set = parser.parse(jwksString);
        Set<PublicJwk<?>> publicJwks = new HashSet<>();
        for (Jwk<?> jwk : set.getKeys()) {
            if (jwk instanceof PublicJwk<?>) {
                publicJwks.add((PublicJwk<?>) jwk);
            }
        }
        return publicJwks;
    }
}
