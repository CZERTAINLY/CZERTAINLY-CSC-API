package com.czertainly.csc.signing.configuration.process.configuration;

import com.czertainly.csc.api.auth.CscAuthenticationToken;

import java.util.UUID;


public record SessionTokenConfiguration(
        UUID sessionId,
        CscAuthenticationToken cscAuthenticationToken
) implements TokenConfiguration {}