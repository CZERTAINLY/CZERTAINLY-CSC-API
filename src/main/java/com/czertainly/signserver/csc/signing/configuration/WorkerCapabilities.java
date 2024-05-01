package com.czertainly.signserver.csc.signing.configuration;


import java.util.List;

public record WorkerCapabilities(
        List<String> signatureQualifiers,
        SignatureFormat signatureFormat,
        ConformanceLevel conformanceLevel,
        SignaturePackaging signaturePackaging
        ) {
}
