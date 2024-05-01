package com.czertainly.signserver.csc.api.auth;

import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class TokenValidator {

    JwtParser jwtParser;

    public TokenValidator(KeyLocator keyLocator, @Value("${idp.issuer}") String issuer,
                          @Value("${idp.audience}") String audience,
                          @Value("${idp.clockSkewSeconds}") int clockSkewSeconds
    ) {
        jwtParser = Jwts.parser()
                        .keyLocator(keyLocator)
                        .requireAudience(audience)
                        .requireIssuer(issuer)
                        .clockSkewSeconds(clockSkewSeconds)
                        .build();
    }

    public Result<Jws<Claims>, ErrorWithDescription> validate(String token) {
        try {
            Jws<Claims> jwt = jwtParser.parseSignedClaims(token);
            return Result.ok(jwt);
        } catch (JwtException | IllegalArgumentException e) {
            return Result.error(new ErrorWithDescription("JWTValidationError", e.getMessage()));
        }
    }


}
