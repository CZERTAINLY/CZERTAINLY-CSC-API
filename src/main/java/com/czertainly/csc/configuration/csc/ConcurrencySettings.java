package com.czertainly.csc.configuration.csc;

import jakarta.validation.constraints.Min;

public record ConcurrencySettings(
        @Min(1) Integer maxKeyGeneration,
        @Min(1) Integer maxKeyDeletion
) {
    public ConcurrencySettings {
        if (maxKeyGeneration == null) maxKeyGeneration = 10;
        if (maxKeyDeletion == null) maxKeyDeletion = 10;
    }
}
