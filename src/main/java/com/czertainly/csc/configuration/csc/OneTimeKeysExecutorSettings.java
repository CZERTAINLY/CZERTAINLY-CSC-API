package com.czertainly.csc.configuration.csc;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public record OneTimeKeysExecutorSettings(
        @Min(1) int coreSize,
        @Min(1) int maxSize,
        @Min(0) int queueCapacity,
        @NotBlank String threadNamePrefix
) {}
