package com.otilm.csc.model;

import com.otilm.csc.crypto.SignatureAlgorithm;
import com.otilm.csc.signing.configuration.ConformanceLevel;
import com.otilm.csc.signing.configuration.SignatureFormat;
import com.otilm.csc.signing.configuration.SignaturePackaging;

import java.util.Map;

public record DocumentContentToSign(
        String content,
        SignatureFormat signatureFormat,
        ConformanceLevel conformanceLevel,
        SignatureAlgorithm signatureAlgorithm,
        Map<String, String> signedAttributes,
        SignaturePackaging signaturePackaging
) {
}
