package com.czertainly.csc.utils.jwt;

import com.czertainly.csc.api.auth.JwksRepository;
import com.czertainly.csc.api.auth.exceptions.JwkLookupException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.ProtectedHeader;

import java.security.Key;
import java.security.PublicKey;

public class TestKeyLocator extends LocatorAdapter<Key> {

    private final JWKSet jwkSet;

    public TestKeyLocator(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    protected Key locate(JweHeader header) {
        return getPublicKey(header);
    }

    @Override
    protected Key locate(JwsHeader header) {
        return getPublicKey(header);
    }

    private PublicKey getPublicKey(ProtectedHeader header) {
        JWK jwk = jwkSet.getKeyByKeyId(header.getKeyId());
        if (jwk == null) {
            throw new JwkLookupException("Failed to locate key with kid: " + header.getKeyId());
        }
        KeyType keyType = jwk.getKeyType();

        try {
            if (keyType == KeyType.RSA) {
                return jwk.toRSAKey().toPublicKey();
            } else if (keyType == KeyType.EC) {
                return jwk.toECKey().toPublicKey();
            } else {
                throw new JwkLookupException("Unsupported key type: " + keyType);
            }
        } catch (JOSEException e) {
            throw new JwkLookupException("Failed to locate key with kid: " + header.getKeyId(), e);
        }
    }
}
