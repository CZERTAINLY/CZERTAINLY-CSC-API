package com.czertainly.signserver.csc.api.auth.authn;

import com.czertainly.signserver.csc.api.auth.CscAuthenticationToken;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.api.auth.SignatureActivationDataBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.*;

public class CscJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    public static final String CREDENTIAL_SCOPE = "SCOPE_CREDENTIAL";


    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        AbstractAuthenticationToken token = jwtAuthenticationConverter.convert(source);
        if (token.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch(CREDENTIAL_SCOPE::equalsIgnoreCase)) {
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
        return builder.build();
    }

    private String extractStringClaim(Jwt jwt, String claimName) {
        return jwt.getClaimAsString(claimName);
    }

    private int extractIntegerClaim(Jwt jwt, String claimName) {
        String claim = jwt.getClaimAsString(claimName);
        if (claim == null) {
            throw new IllegalArgumentException("Missing a required claim '" + claimName + "' in the credential access token.");
        }
        try {
            return Integer.parseInt(claim);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Claim '" + claimName + "' must represent a natural number.");
        }
    }

    private Set<String> extractSetClaim(Jwt jwt, String claimName) {
        List<String> claim = jwt.getClaimAsStringList(claimName);
        return claim != null ? new HashSet<>(claim): Collections.emptySet();
    }

}
