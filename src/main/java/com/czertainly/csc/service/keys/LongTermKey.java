package com.czertainly.csc.service.keys;

import com.czertainly.csc.model.signserver.CryptoToken;

import java.time.ZonedDateTime;
import java.util.StringJoiner;
import java.util.UUID;

public class LongTermKey extends SigningKey {
    public LongTermKey(UUID id, CryptoToken cryptoToken, String keyAlias, String keyAlgorithm
    ) {
        super(id, cryptoToken, keyAlias, keyAlgorithm, true, ZonedDateTime.now());
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", LongTermKey.class.getSimpleName() + "[", "]")
                .add("id=" + this.id().toString())
                .add("keyAlias=" + this.keyAlias())
                .toString();
    }
}
