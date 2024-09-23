package com.czertainly.csc.utils.jwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.platform.commons.JUnitException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

public class TestJwkGenerator {

    public static final String defaultKeyId = UUID.randomUUID().toString();
    public static final JWK defaultKey = generate("RSA", defaultKeyId);
    public static final JWKSet defaultJwkSet = new JWKSet(defaultKey);
    public static final JWKSource<SecurityContext> defaultJwkSource = new ImmutableJWKSet<>(defaultJwkSet);

    public TestJwkGenerator() {
    }

    public static JWK generate(String algorithm, String keyId) {

        KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new JUnitException("Failed to generate a KeyPair for Test JWK", e);
        }
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(keyId)
                .build();
    }

    public static JWKSource<SecurityContext> getJwkSource(JWK jwk) {
        return new ImmutableJWKSet<>(new JWKSet(jwk));
    }

}
