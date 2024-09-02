package com.czertainly.csc.api.auth;


import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class SADParser {

    public static final Logger logger = LogManager.getLogger(SADParser.class);


    TokenValidator validator;

    public SADParser(TokenValidator validator) {
        this.validator = validator;
    }

    public SignatureActivationData parse(String sad) {
        return validator.validate(sad)
                        .mapError(error -> error.extend("Failed to validate SAD"))
                        .map(this::extractSadFromToken)
                        .consumeError(
                                error -> {
                                    throw new InvalidInputDataException(error.toString());
                                }
                        ).unwrap();
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
        } else if (hashes instanceof String s) {
            var parts = s.split(",");
            return Stream.of(parts).map(String::strip).collect(Collectors.toSet());
        } else {
            logger.warn("The 'hashes' claim is not a list. The claim will be ignored.");
            return Set.of();
        }

    }
}
