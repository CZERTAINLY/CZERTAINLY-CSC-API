package com.czertainly.csc.signing.configuration.process.configuration;

import com.czertainly.csc.api.auth.CscAuthenticationToken;

public record OneTimeTokenConfiguration(
        CscAuthenticationToken cscAuthenticationToken
) implements TokenConfiguration {



}
