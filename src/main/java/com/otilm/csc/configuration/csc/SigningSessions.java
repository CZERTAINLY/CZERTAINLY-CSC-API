package com.otilm.csc.configuration.csc;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Duration;

public record SigningSessions(
        @NotNull Duration expiredSessionsKeepTime,
        Duration assignedKeyLifetime,
        @NotBlank String generateCronExpression,
        @NotBlank String cleanupCronExpression
) {}
