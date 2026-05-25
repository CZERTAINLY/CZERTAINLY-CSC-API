package com.otilm.csc.utils.signing.process;

import com.otilm.csc.signing.configuration.process.configuration.TokenConfiguration;
import org.instancio.Instancio;

public class TestTokenConfiguration implements TokenConfiguration {

    public static TestTokenConfiguration any() {
        return Instancio.create(TestTokenConfiguration.class);
    }
}