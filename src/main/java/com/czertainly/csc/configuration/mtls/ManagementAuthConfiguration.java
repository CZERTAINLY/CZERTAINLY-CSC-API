package com.czertainly.csc.configuration.mtls;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
@ConfigurationProperties(prefix = "csc.management.auth")
public record ManagementAuthConfiguration(
        ManagementAuthType type,
        ManagementMtlsProperties certificate
) {
    public ManagementAuthConfiguration {
        type = type != null ? type : ManagementAuthType.OAUTH2;
        certificate = certificate != null ? certificate : new ManagementMtlsProperties(null, List.of(), List.of(), List.of(), null);
    }
}
