package com.czertainly.signserver.csc.model;

import com.czertainly.signserver.csc.signing.configuration.ConformanceLevel;
import com.czertainly.signserver.csc.signing.configuration.SignatureFormat;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;

import java.util.List;
import java.util.Map;


public record DocumentDigestsToSign(List<String> hashes, SignatureFormat signatureFormat, ConformanceLevel conformanceLevel,
                                    String keyAlgorithm, String digestAlgorithm, String signAlgoParams,
                                    Map<String, String> signedAttributes, SignaturePackaging signaturePackaging) {

    public String getSignatureAlgorithm() {
        return digestAlgorithm + "With" + keyAlgorithm;
    }

}
