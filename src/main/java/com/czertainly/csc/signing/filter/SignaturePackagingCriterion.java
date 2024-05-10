package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.signing.configuration.SignaturePackaging;

public class SignaturePackagingCriterion implements Criterion<WorkerCapabilities>{
    private final SignaturePackaging packaging;

    public SignaturePackagingCriterion(SignaturePackaging packaging) {
        this.packaging = packaging;
    }

    public boolean matches(WorkerCapabilities element) {
        return element.signaturePackaging().equals(packaging);
    }
}
