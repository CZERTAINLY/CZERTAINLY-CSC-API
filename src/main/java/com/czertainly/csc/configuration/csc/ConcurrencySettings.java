package com.czertainly.csc.configuration.csc;

import jakarta.validation.constraints.Min;

public record ConcurrencySettings(
        @Min(1) Integer maxKeyGeneration,
        @Min(1) Integer maxKeyDeletion
) {
    public ConcurrencySettings(@Min(1) Integer maxKeyGeneration, @Min(1) Integer maxKeyDeletion) {
        this.maxKeyGeneration = (maxKeyGeneration == null) ? 10 : maxKeyGeneration;
        this.maxKeyDeletion = (maxKeyDeletion == null) ? 10 : maxKeyDeletion;
    }
}
