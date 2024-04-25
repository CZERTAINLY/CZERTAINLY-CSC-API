package com.czertainly.signserver.csc.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

//@ConfigurationProperties(prefix = "idp")
public record IdpConfiguration(
        String issuer,
        String audience,
        String jwksUri
) {
}
