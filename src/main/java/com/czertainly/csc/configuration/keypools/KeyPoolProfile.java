package com.czertainly.csc.configuration.keypools;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record KeyPoolProfile(
        @NotBlank String name,
        @NotBlank String keyAlgorithm,
        @NotBlank String keySpecification,
        @NotBlank String keyPrefix,
        @Min(1) int desiredSize,
        @Min(1) int maxKeysGeneratedPerReplenish,
        @NotNull KeyUsageDesignation designatedUsage
) {

}
