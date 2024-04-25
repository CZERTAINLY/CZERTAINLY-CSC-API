package com.czertainly.signserver.csc.model;

import com.czertainly.signserver.csc.signing.configuration.ConformanceLevel;
import com.czertainly.signserver.csc.signing.configuration.SignatureFormat;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;

import java.util.Map;


public record Document(String content, SignatureFormat signatureFormat, ConformanceLevel conformanceLevel,
                       String keyAlgorithm, String digestAlgorithm, String signAlgoParams,
                       Map<String, String> signedAttributes, SignaturePackaging signaturePackaging) {
}
