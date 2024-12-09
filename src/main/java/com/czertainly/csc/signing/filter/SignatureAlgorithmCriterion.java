package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.WorkerCapabilities;

public class SignatureAlgorithmCriterion implements Criterion<WorkerCapabilities> {

    private final String algorithm;

    public SignatureAlgorithmCriterion(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        return element.supportedSignatureAlgorithms().stream()
                      .anyMatch(alg -> alg.equalsIgnoreCase(algorithm));
    }
}
