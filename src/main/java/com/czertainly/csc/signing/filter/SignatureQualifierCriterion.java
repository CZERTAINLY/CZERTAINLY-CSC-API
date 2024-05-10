package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.WorkerCapabilities;

public class SignatureQualifierCriterion implements Criterion<WorkerCapabilities> {

    private final String signatureQualifier;

    public SignatureQualifierCriterion(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        return element.signatureQualifiers().contains(signatureQualifier);
    }
}
