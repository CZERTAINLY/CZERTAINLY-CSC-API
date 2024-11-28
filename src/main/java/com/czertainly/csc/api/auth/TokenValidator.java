package com.czertainly.csc.api.auth;

import com.czertainly.csc.api.auth.exceptions.JwkLookupException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class TokenValidator {

    JwtParser jwtParser;

    public TokenValidator(LocatorAdapter<Key> keyLocator, IdpConfiguration idpConfiguration) {
        jwtParser = Jwts.parser()
                        .keyLocator(keyLocator)
                        .requireAudience(idpConfiguration.audience())
                        .requireIssuer(idpConfiguration.issuer())
                        .clockSkewSeconds(idpConfiguration.clockSkewSeconds().getSeconds())
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
