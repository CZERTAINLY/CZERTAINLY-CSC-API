package com.czertainly.csc.model;

import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignaturePackaging;

import java.util.Map;

public record DocumentContentToSign(
        String content,
        SignatureFormat signatureFormat,
        ConformanceLevel conformanceLevel,
        String keyAlgorithm,
        String digestAlgorithm,
        String signAlgoParams,
        Map<String, String> signedAttributes,
        SignaturePackaging signaturePackaging
) {
    public SignatureAlgorithm signatureAlgorithm() {
        return SignatureAlgorithm.of(keyAlgorithm, digestAlgorithm);
    }
}
