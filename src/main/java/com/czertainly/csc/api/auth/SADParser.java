package com.czertainly.csc.api.auth;


import com.czertainly.csc.controllers.exceptions.BadRequestException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

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
               .withHashes(extractHashes(claims))
               .withClientData(claims.get("clientData", String.class));

        claims.entrySet().stream()
              .filter(entry -> !SignatureActivationDataBuilder.knownClaims.contains(entry.getKey()))
              .forEach(entry -> {
                  try {
                      builder.withOtherAttribute(entry.getKey(), entry.getValue().toString());
                  } catch (Exception e) {
                      logger.warn("Error parsing SAD attribute {}. Attribute will be ignored.", entry.getKey());
                  }
              });

        return builder.build();
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractHashes(Claims claims) {
        Object hashes = claims.get("hashes");
        if (hashes instanceof List) {
            if (((List<?>) hashes).getFirst() instanceof String) {

                return Set.copyOf((List<String>) hashes);
            } else {
                logger.warn("The 'hashes' claim is not a list of strings. The claim will be ignored.");
                return Set.of();
            }
        } else {
            logger.warn("The 'hashes' claim is not a list. The claim will be ignored.");
            return Set.of();
        }

    }
}
