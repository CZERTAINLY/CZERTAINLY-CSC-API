package com.czertainly.csc.utils.jwt;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TestJwtBuilder {

    private final JwtEncoder jwtEncoder;

    private String scope;
    private String userID;
    private String numOfSignatures;
    private String signatureQualifier;
    private String credentialId;
    private String hashes;
    private String hashAlgorithmOID;
    private Instant iat;
    private Instant exp;
    private final Map<String, String> claims = new HashMap<>();

    public TestJwtBuilder() {
        jwtEncoder = new NimbusJwtEncoder(TestJwkGenerator.defaultJwkSource);
    }

    public TestJwtBuilder(JWKSource<SecurityContext> jwkSource) {
        this.jwtEncoder = new NimbusJwtEncoder(jwkSource);
    }

    public Jwt build() {
        JwsHeader jwsHeader = getJwsHeader();
        JwtClaimsSet claims = getJwtClaimsSet();
        JwtEncoderParameters params = JwtEncoderParameters.from(jwsHeader, claims);
        return jwtEncoder.encode(params);
    }

    private JwtClaimsSet getJwtClaimsSet() {
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder();
        if (scope != null) {
            builder.claim("scope", scope);
        }

        if (userID != null) {
            builder.claim("userID", userID);
        }

        if (numOfSignatures != null) {
            builder.claim("numSignatures", numOfSignatures);
        }

        if (signatureQualifier != null) {
            builder.claim("signatureQualifier", signatureQualifier);
        }

        if (credentialId != null) {
            builder.claim("credentialID", credentialId);
        }

        if (hashes != null) {
            builder.claim("hashes", hashes);
        }

        if (hashAlgorithmOID != null) {
            builder.claim("hashAlgorithmOID", hashAlgorithmOID);
        }

        for (Map.Entry<String, String> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }

        if (iat != null) {
            builder.claim("iat", iat.getEpochSecond());
        } else {
            builder.claim("iat", Instant.now().getEpochSecond());
        }

        if (exp != null) {
            builder.claim("exp", exp.getEpochSecond());
        } else {
            builder.claim("exp", Instant.now().plusSeconds(3600).getEpochSecond());
        }

        return builder.build();
    }

    public TestJwtBuilder withScope(String scope) {
        this.scope = scope;
        return this;
    }

    public TestJwtBuilder withUserID(String userID) {
        this.userID = userID;
        return this;
    }

    public TestJwtBuilder withNumOfSignatures(String numOfSignatures) {
        this.numOfSignatures = numOfSignatures;
        return this;
    }

    public TestJwtBuilder withSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
        return this;
    }

    public TestJwtBuilder withCredentialID(String credentialId) {
        this.credentialId = credentialId;
        return this;
    }

    public TestJwtBuilder withHashes(Set<String> hashes) {
        this.hashes = String.join(",", hashes);
        return this;
    }

    public TestJwtBuilder withHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
        return this;
    }


    public TestJwtBuilder withClaim(String key, String value) {
        this.claims.put(key, value);
        return this;
    }

    public TestJwtBuilder withClaims(Map<String, String> claims) {
        this.claims.putAll(claims);
        return this;
    }

    public TestJwtBuilder withIssuedAt(Instant iat) {
        this.iat = iat;
        return this;
    }

    public TestJwtBuilder withExpiration(Instant exp) {
        this.exp = exp;
        return this;
    }


    private JwsHeader getJwsHeader() {
        return JwsHeader.with(SignatureAlgorithm.RS256)
                        .type("JWT")
                        .build();
    }
}
