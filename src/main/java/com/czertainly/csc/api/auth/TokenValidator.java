package com.czertainly.csc.api.auth;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
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

    public Result<Jws<Claims>, TextError> validate(String token) {
        try {
            Jws<Claims> jwt = jwtParser.parseSignedClaims(token);
            return Result.success(jwt);
        } catch (JwtException | IllegalArgumentException e) {
            return Result.error(TextError.of(e));
        }
    }


}
