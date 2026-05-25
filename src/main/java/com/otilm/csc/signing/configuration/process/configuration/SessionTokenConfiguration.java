package com.otilm.csc.signing.configuration.process.configuration;

import com.otilm.csc.api.auth.CscAuthenticationToken;

import java.util.UUID;


public record SessionTokenConfiguration(
        UUID sessionId,
        CscAuthenticationToken cscAuthenticationToken
) implements TokenConfiguration {}