package com.czertainly.csc.api.auth;

import com.czertainly.csc.api.auth.exceptions.JwkLookupException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class TokenValidator {

    JwtParser jwtParser;

    public TokenValidator(LocatorAdapter<Key> keyLocator, @Value("${idp.issuer}") String issuer,
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
            Date iat = jwt.getPayload().getIssuedAt();
            if (iat == null) {
                return Result.error(TextError.of("Missing issued at claim"));
            } else if (iat.after(new Date())) {
                return Result.error(TextError.of("Token issued at future"));
            }

            return Result.success(jwt);
        } catch (JwtException | JwkLookupException | IllegalArgumentException e) {
            return Result.error(TextError.of(e));
        }
    }


}
