package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;

public class SignatureFormatCriterion implements Criterion<WorkerCapabilities> {

    private final SignatureFormat signatureFormat;

    public SignatureFormatCriterion(SignatureFormat signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        return element.signatureFormat().equals(signatureFormat);
    }
}
