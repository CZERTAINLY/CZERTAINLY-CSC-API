package com.czertainly.csc.utils.jwt;

import com.czertainly.csc.api.auth.TokenValidator;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import com.czertainly.csc.utils.configuration.IdpConfigurationBuilder;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import static com.czertainly.csc.utils.jwt.Constants.*;

public class TestIdp {

    public static final String TEST_ISSUER = "com.czertainly.csc.test-issuer";
    public static final String TEST_AUDIENCE = "com.czertainly.csc.test-audience";

    public static final String defaultKeyId = UUID.randomUUID().toString();
    public static final JWK defaultKey = TestJwkGenerator.generate("RSA", defaultKeyId);
    public static final JWKSet defaultJwkSet = new JWKSet(defaultKey);
    public static final JWKSource<SecurityContext> defaultJwkSource = new ImmutableJWKSet<>(defaultJwkSet);
    public static final TestKeyLocator defaultKeyLocator = new TestKeyLocator(defaultJwkSet);
    public static final IdpConfiguration idpConfiguration = new IdpConfigurationBuilder()
            .withAudience(TEST_AUDIENCE)
            .withIssuer(TEST_ISSUER)
            .withClockSkewSeconds(Duration.ofSeconds(1))
            .build();
    public static final TokenValidator defaultTokenValidator = new TokenValidator(defaultKeyLocator, idpConfiguration);


    public static Jwt credentialToken() {
        return new TestJwtBuilder(defaultJwkSource).withScope(CREDENTIAL_SCOPE)
                                                   .withUserID("franta.pepa.jednicka")
                                                   .withNumOfSignatures("1")
                                                   .withSignatureQualifier("eu_eidas_aes")
                                                   .withCredentialID(UUID.randomUUID().toString())
                                                   .withHashAlgorithmOID(NISTObjectIdentifiers.id_sha256.getId())
                                                   .withHashes(
                                                           Set.of(
                                                                   "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=",
                                                                   "Njy1yEOux68lDklWf 4nBjiMpXLAyZHqqMOxFcM3Ojo="
                                                           )
                                                   )
                                                   .withClaim("aud", TEST_AUDIENCE)
                                                   .withClaim("iss", TEST_ISSUER)
                                                   .build();
    }

}
