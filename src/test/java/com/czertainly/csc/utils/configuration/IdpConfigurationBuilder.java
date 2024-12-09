package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.configuration.idp.IdpClientAuth;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.time.Duration;

import static org.instancio.Select.field;

public class IdpConfigurationBuilder {

    InstancioClassApi<IdpConfiguration> partial = Instancio.of(IdpConfiguration.class);

    public static IdpConfiguration anIdpConfiguration() {
        return Instancio.of(IdpConfiguration.class)
                .create();
    }

    public static IdpConfigurationBuilder create() {
        return new IdpConfigurationBuilder();
    }

    public IdpConfigurationBuilder withIssuer(String issuer) {
        partial.set(field(IdpConfiguration::issuer), issuer);
        return this;
    }

    public IdpConfigurationBuilder withAudience(String audience) {
        partial.set(field(IdpConfiguration::audience), audience);
        return this;
    }

    public IdpConfigurationBuilder withClockSkewSeconds(Duration clockSkewSeconds) {
        partial.set(field(IdpConfiguration::clockSkewSeconds), clockSkewSeconds);
        return this;
    }

    public IdpConfigurationBuilder withUserInfoUrl(String userInfoUrl) {
        partial.set(field(IdpConfiguration::userInfoUrl), userInfoUrl);
        return this;
    }

    public IdpConfigurationBuilder withBaseUrl(String baseUrl) {
        partial.set(field(IdpConfiguration::baseUrl), baseUrl);
        return this;
    }

    public IdpConfigurationBuilder withJwksUri(String jwksUri) {
        partial.set(field(IdpConfiguration::jwksUri), jwksUri);
        return this;
    }

    public IdpConfigurationBuilder withTruststoreBundle(String truststoreBundle) {
        partial.set(field(IdpConfiguration::truststoreBundle), truststoreBundle);
        return this;
    }

    public IdpConfigurationBuilder withAuth(IdpClientAuth auth) {
        partial.set(field(IdpConfiguration::client), auth);
        return this;
    }

    public IdpConfiguration build() {
        return partial.create();
    }

}
