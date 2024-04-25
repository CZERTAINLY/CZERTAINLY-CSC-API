package com.czertainly.signserver.csc.api.auth;


import com.czertainly.signserver.csc.controllers.exceptions.BadRequestException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

@Component
public class SADParser {

    public static final Logger logger = LogManager.getLogger(SADParser.class);

    TokenValidator validator;

    public SADParser(TokenValidator validator) {
        this.validator = validator;
    }

    public SignatureActivationData parse(String sad) {
        return validator.validate(sad)
                        .with(
                                this::extractSadFromToken,
                                error -> {
                                    logger.debug("The SAD is not valid. {}", error.description());
                                    throw new BadRequestException("invalid_request", "The SAD is not valid");
                                }
                        );
    }

    private SignatureActivationData extractSadFromToken(Jws<Claims> token) {
        Claims claims = token.getPayload();
        SignatureActivationDataBuilder builder = new SignatureActivationDataBuilder();
        builder.withCredentialID(claims.get("credentialID", String.class))
               .withSignatureQualifier(claims.get("signatureQualifier", String.class))
               .withHashAlgorithmOID(claims.get("hashAlgorithmOID", String.class))
               .withNumSignatures(Integer.parseInt(claims.get("numSignatures", String.class)))
               .withClientData(claims.get("clientData", String.class));

        return builder.build();
    }
}
