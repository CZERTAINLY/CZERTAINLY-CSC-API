package com.czertainly.csc.configuration.idp;

import jakarta.validation.constraints.NotNull;


public record IdpClientAuth(
        @NotNull(message = "Authentication type is required. Possible values are [NONE, CERTIFICATE]")
        IdpAuthentication authType,
        IdpClientAuthCertificate certificate
) {
    public record IdpClientAuthCertificate(
            String keystoreBundle
    ) {}
}
