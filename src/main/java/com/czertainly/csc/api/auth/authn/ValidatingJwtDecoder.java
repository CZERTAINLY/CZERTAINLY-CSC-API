package com.czertainly.csc.api.auth.authn;

import com.czertainly.csc.api.auth.TokenValidator;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

@Component
public class ValidatingJwtDecoder implements JwtDecoder {

    TokenValidator validator;

    public ValidatingJwtDecoder(TokenValidator validator) {
        this.validator = validator;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Result<Jws<Claims>, ErrorWithDescription> result = validator.validate(token);
        return result.with(
                jwt -> Jwt.withTokenValue(token)
                          .headers((h) -> h.putAll(jwt.getHeader()))
                          .claims((c) -> {
                              c.putAll(jwt.getPayload());
                              c.put(JwtClaimNames.IAT, jwt.getPayload().getIssuedAt().toInstant());
                              c.put(JwtClaimNames.EXP, jwt.getPayload().getExpiration().toInstant());
                          })
                          .build(),
                error -> {
                    throw new BadJwtException(error.description());
                }
        );
    }
}
