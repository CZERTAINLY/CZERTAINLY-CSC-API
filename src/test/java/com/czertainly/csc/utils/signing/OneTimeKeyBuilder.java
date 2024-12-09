package com.czertainly.csc.utils.signing;

import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.service.keys.OneTimeKey;
import com.czertainly.csc.service.keys.SigningKey;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.time.ZonedDateTime;
import java.util.UUID;

import static org.instancio.Select.field;


public class OneTimeKeyBuilder {

    InstancioClassApi<OneTimeKey> partial = Instancio.of(OneTimeKey.class);

    public static OneTimeKey aOneTimeKey() {
        return Instancio.of(OneTimeKey.class)
                        .create();
    }

    public static OneTimeKeyBuilder create() {
        return new OneTimeKeyBuilder();
    }

    public OneTimeKeyBuilder withId(UUID id) {
        partial.set(field(OneTimeKey::id), id);
        return this;
    }

    public OneTimeKeyBuilder withCryptoToken(CryptoToken cryptoToken) {
        partial.set(field(OneTimeKey::cryptoToken), cryptoToken);
        return this;
    }

    public OneTimeKeyBuilder withKeyAlias(String keyAlias) {
        partial.set(field(OneTimeKey::keyAlias), keyAlias);
        return this;
    }

    public OneTimeKeyBuilder withKeyAlgorithm(String keyAlgorithm) {
        partial.set(field(OneTimeKey::keyAlgorithm), keyAlgorithm);
        return this;
    }

    public OneTimeKeyBuilder withInUse(Boolean inUse) {
        partial.set(field(OneTimeKey::inUse), inUse);
        return this;
    }

    public OneTimeKeyBuilder withAcquiredAt(ZonedDateTime acquiredAt) {
        partial.set(field(OneTimeKey::acquiredAt), acquiredAt);
        return this;
    }

    public OneTimeKey build() {
        return partial.create();
    }

}
