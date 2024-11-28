package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.configuration.idp.IdpConfiguration;
import jakarta.validation.constraints.NotBlank;
import org.instancio.Instancio;

import java.time.Duration;

import static org.instancio.Select.field;

public class IdpConfigurationBuilder {
    String issuer;
    @NotBlank String audience;
    Duration clockSkewSeconds;

    public static IdpConfiguration anIdpConfiguration() {
        return Instancio.of(IdpConfiguration.class)
                .create();
    }

    public IdpConfigurationBuilder withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public IdpConfigurationBuilder withAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public IdpConfigurationBuilder withClockSkewSeconds(Duration clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
        return this;
    }

    public IdpConfiguration build() {
        var partial = Instancio.of(IdpConfiguration.class);
        if (issuer != null) {
            partial.set(field(IdpConfiguration::issuer), issuer);
        }

        if (audience != null) {
            partial.set(field(IdpConfiguration::audience), audience);
        }

        if (clockSkewSeconds != null) {
            partial.set(field(IdpConfiguration::clockSkewSeconds), clockSkewSeconds);
        }
        return partial.create();
    }

}
