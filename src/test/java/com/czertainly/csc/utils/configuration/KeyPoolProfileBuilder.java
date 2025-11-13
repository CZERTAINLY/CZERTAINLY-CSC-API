package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.configuration.keypools.KeyPoolProfile;
import com.czertainly.csc.configuration.keypools.KeyUsageDesignation;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import static org.instancio.Select.field;

public class KeyPoolProfileBuilder {

    InstancioClassApi<KeyPoolProfile> partial = Instancio.of(KeyPoolProfile.class);

    public static KeyPoolProfile aKeyPoolProfile() {
        return Instancio.of(KeyPoolProfile.class)
                        .create();
    }

    public static KeyPoolProfileBuilder create() {
        return new KeyPoolProfileBuilder();
    }

    public KeyPoolProfileBuilder withName(String name) {
        partial.set(field(KeyPoolProfile::name), name);
        return this;
    }

    public KeyPoolProfileBuilder withKeyAlgorithm(String keyAlgorithm) {
        partial.set(field(KeyPoolProfile::keyAlgorithm), keyAlgorithm);
        return this;
    }

    public KeyPoolProfileBuilder withKeySpecification(String keySpecification) {
        partial.set(field(KeyPoolProfile::keySpecification), keySpecification);
        return this;
    }

    public KeyPoolProfileBuilder withKeyPrefix(String keyPrefix) {
        partial.set(field(KeyPoolProfile::keyPrefix), keyPrefix);
        return this;
    }

    public KeyPoolProfileBuilder withDesiredSize(int desiredSize) {
        partial.set(field(KeyPoolProfile::desiredSize), desiredSize);
        return this;
    }

    public KeyPoolProfileBuilder withMaxKeysGeneratedPerReplenish(int maxKeysGeneratedPerReplenish) {
        partial.set(field(KeyPoolProfile::maxKeysGeneratedPerReplenish), maxKeysGeneratedPerReplenish);
        return this;
    }

    public KeyPoolProfileBuilder withDesignatedUsage(KeyUsageDesignation designatedUsage) {
        partial.set(field(KeyPoolProfile::designatedUsage), designatedUsage);
        return this;
    }

    public KeyPoolProfile build() {
        return partial.create();
    }
}
