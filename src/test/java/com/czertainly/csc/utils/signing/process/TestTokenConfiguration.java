package com.czertainly.csc.utils.signing.process;

import com.czertainly.csc.signing.configuration.process.configuration.TokenConfiguration;
import org.instancio.Instancio;

public class TestTokenConfiguration implements TokenConfiguration {

    public static TestTokenConfiguration any() {
        return Instancio.create(TestTokenConfiguration.class);
    }
}