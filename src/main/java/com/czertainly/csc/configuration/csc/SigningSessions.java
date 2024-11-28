package com.czertainly.csc.configuration.csc;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Duration;

public record SigningSessions(
        @NotNull Duration expiredSessionsKeepTime,
        @NotBlank String cleanupCronExpression
) {}
