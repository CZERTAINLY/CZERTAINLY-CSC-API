package com.czertainly.csc.model;

import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;

import java.util.List;
import java.util.Map;


public record DocumentDigestsToSign(
        List<String> hashes,
        SignatureFormat signatureFormat,
        ConformanceLevel conformanceLevel,
        SignatureAlgorithm signatureAlgorithm,
        Map<String, String> signedAttributes,
        SignaturePackaging signaturePackaging
) {
}
