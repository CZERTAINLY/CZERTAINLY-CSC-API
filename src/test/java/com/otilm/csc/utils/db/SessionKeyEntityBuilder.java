package com.otilm.csc.utils.db;

import com.otilm.csc.repository.entities.SessionKeyEntity;

import java.time.ZonedDateTime;
import java.util.UUID;

public class SessionKeyEntityBuilder {

    private UUID id = UUID.randomUUID();
    private int cryptoTokenId = 1;
    private String keyAlias = "test-key";
    private String keyAlgorithm = "RSA";
    private boolean inUse = false;
    private ZonedDateTime acquiredAt = null;

    public static SessionKeyEntityBuilder aSessionKey() {
        return new SessionKeyEntityBuilder();
    }

    public SessionKeyEntityBuilder withId(UUID id) {
        this.id = id;
        return this;
    }

    public SessionKeyEntityBuilder withAlias(String alias) {
        this.keyAlias = alias;
        return this;
    }

    public SessionKeyEntityBuilder withTokenId(int tokenId) {
        this.cryptoTokenId = tokenId;
        return this;
    }

    public SessionKeyEntityBuilder withAlgorithm(String algorithm) {
        this.keyAlgorithm = algorithm;
        return this;
    }

    public SessionKeyEntityBuilder withInUse(boolean inUse) {
        this.inUse = inUse;
        return this;
    }

    public SessionKeyEntityBuilder withAcquiredAt(ZonedDateTime acquiredAt) {
        this.acquiredAt = acquiredAt;
        return this;
    }

    public SessionKeyEntity build() {
        return new SessionKeyEntity(id, cryptoTokenId, keyAlias, keyAlgorithm, inUse, acquiredAt);
    }
}
