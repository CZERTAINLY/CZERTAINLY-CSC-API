package com.czertainly.csc.configuration.mtls;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "csc.management.auth.certificate")
public record ManagementMtlsProperties(
        String truststoreBundle,
        List<String> allowedIssuers,
        List<String> allowedSubjects,
        List<String> allowedFingerprints,
        String clientCertificateHeader
) {
    public ManagementMtlsProperties {
        allowedIssuers = allowedIssuers != null ? allowedIssuers : List.of();
        allowedSubjects = allowedSubjects != null ? allowedSubjects : List.of();
        allowedFingerprints = allowedFingerprints != null ? allowedFingerprints : List.of();
    }
}
