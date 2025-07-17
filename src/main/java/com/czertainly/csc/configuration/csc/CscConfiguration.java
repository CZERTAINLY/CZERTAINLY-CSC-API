package com.czertainly.csc.configuration.csc;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "csc")
public record CscConfiguration(
        @NotBlank String name,
        @NotBlank String logo,
        @NotBlank String region,
        @NotBlank String workerConfigurationFile,
        @NotBlank String profilesConfigurationDirectory,
        @NotNull SigningSessions signingSessions,
        @NotNull OneTimeKeysCleanupSettings oneTimeKeys,
        @Valid ConcurrencySettings concurrency
) {}
