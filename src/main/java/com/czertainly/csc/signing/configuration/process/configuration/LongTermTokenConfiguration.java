package com.czertainly.csc.signing.configuration.process.configuration;

import java.util.UUID;

public record LongTermTokenConfiguration(
        UUID credentialId
) implements TokenConfiguration {}