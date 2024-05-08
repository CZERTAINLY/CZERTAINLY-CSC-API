package com.czertainly.signserver.csc.signing.filter;

import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;
import com.czertainly.signserver.csc.signing.configuration.WorkerCapabilities;

public class SignaturePackagingCriterion implements Criterion<WorkerCapabilities>{
    private final SignaturePackaging packaging;

    public SignaturePackagingCriterion(SignaturePackaging packaging) {
        this.packaging = packaging;
    }

    public boolean matches(WorkerCapabilities element) {
        return element.signaturePackaging().equals(packaging);
    }
}
