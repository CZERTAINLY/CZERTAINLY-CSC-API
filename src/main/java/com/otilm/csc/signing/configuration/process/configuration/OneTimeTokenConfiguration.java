package com.otilm.csc.signing.configuration.process.configuration;

import com.otilm.csc.api.auth.CscAuthenticationToken;

public record OneTimeTokenConfiguration(
        CscAuthenticationToken cscAuthenticationToken
) implements TokenConfiguration {


}
