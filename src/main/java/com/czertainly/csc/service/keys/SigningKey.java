package com.czertainly.csc.service.keys;

import com.czertainly.csc.model.signserver.CryptoToken;

import java.time.ZonedDateTime;
import java.util.UUID;

/**
 * Represents a signing key that can be acquired for signing.
 * The signing key is connected to a specific key of a crypto token on Signserver.
 */
public class SigningKey {

    private final UUID id;
    private final CryptoToken cryptoToken;
    private final String keyAlias;
    private final String keyAlgorithm;
    private final Boolean inUse;
    private final ZonedDateTime acquiredAt;

    public SigningKey(UUID id, CryptoToken cryptoToken, String keyAlias, String keyAlgorithm, Boolean inUse,
                      ZonedDateTime acquiredAt
    ) {
        this.id = id;
        this.cryptoToken = cryptoToken;
        this.keyAlias = keyAlias;
        this.keyAlgorithm = keyAlgorithm;
        this.inUse = inUse;
        this.acquiredAt = acquiredAt;
    }

    public UUID id() {
        return id;
    }

    public CryptoToken cryptoToken() {
        return cryptoToken;
    }

    public String keyAlias() {
        return keyAlias;
    }

    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    public Boolean inUse() {
        return inUse;
    }

    public ZonedDateTime acquiredAt() {
        return acquiredAt;
    }
}
