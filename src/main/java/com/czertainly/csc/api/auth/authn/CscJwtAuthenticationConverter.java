package com.czertainly.csc.api.auth.authn;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.auth.SignatureActivationDataBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CscJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    public static final Logger logger = LogManager.getLogger(CscJwtAuthenticationConverter.class);

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    public static final String CREDENTIAL_SCOPE = "SCOPE_CREDENTIAL";

    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        AbstractAuthenticationToken token = jwtAuthenticationConverter.convert(source);
        if (token.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                 .anyMatch(CREDENTIAL_SCOPE::equalsIgnoreCase)) {
            SignatureActivationData signatureActivationData = getSignatureActivationData(source);
            return new CscAuthenticationToken(source, token.getAuthorities(), token.getName(), signatureActivationData);
        }

        return new CscAuthenticationToken(source, token.getAuthorities(), token.getName(), null);
    }

    private SignatureActivationData getSignatureActivationData(Jwt source) {
        SignatureActivationDataBuilder builder = new SignatureActivationDataBuilder();

        builder.withCredentialID(extractStringClaim(source, "credentialID"));
        builder.withSignatureQualifier(extractStringClaim(source, "signatureQualifier"));
        builder.withNumSignatures(extractIntegerClaim(source, "numSignatures"));
        builder.withHashes(extractSetClaim(source, "hashes"));
        builder.withHashAlgorithmOID(extractStringClaim(source, "hashAlgorithmOID"));
        builder.withClientData(extractStringClaim(source, "clientData"));

        source.getClaims().entrySet().stream()
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

    private String extractStringClaim(Jwt jwt, String claimName) {
        return jwt.getClaimAsString(claimName);
    }

    private int extractIntegerClaim(Jwt jwt, String claimName) {
        String claim = jwt.getClaimAsString(claimName);
        if (claim == null) {
            throw new IllegalArgumentException(
                    "Missing a required claim '" + claimName + "' in the credential access token.");
        }
        try {
            return Integer.parseInt(claim);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Claim '" + claimName + "' must represent a natural number.");
        }
    }

    private Set<String> extractSetClaim(Jwt jwt, String claimName) {
        String claimsString = jwt.getClaimAsString(claimName);
        var parts = claimsString.split(",");
        return Stream.of(parts).map(String::strip).collect(Collectors.toSet());
    }

}
