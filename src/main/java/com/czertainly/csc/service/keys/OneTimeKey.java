package com.czertainly.csc.service.keys;

import com.czertainly.csc.model.signserver.CryptoToken;

import java.time.ZonedDateTime;
import java.util.StringJoiner;
import java.util.UUID;

public class OneTimeKey extends SigningKey {
    public OneTimeKey(UUID id, CryptoToken cryptoToken, String keyAlias, String keyAlgorithm, Boolean inUse,
                      ZonedDateTime acquiredAt
    ) {
        super(id, cryptoToken, keyAlias, keyAlgorithm, inUse, acquiredAt);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", SessionKey.class.getSimpleName() + "[", "]")
                .add("id=" + this.id().toString())
                .add("keyAlias=" + this.keyAlias())
                .toString();
    }
}
