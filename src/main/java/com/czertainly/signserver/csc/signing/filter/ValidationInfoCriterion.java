package com.czertainly.signserver.csc.signing.filter;

import com.czertainly.signserver.csc.signing.configuration.WorkerCapabilities;

public class ValidationInfoCriterion implements Criterion<WorkerCapabilities> {

    private final boolean returnValidationInfo;

    public ValidationInfoCriterion(boolean returnValidationInfo) {
        this.returnValidationInfo = returnValidationInfo;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        return element.returnsValidationInfo() == returnValidationInfo;
    }
}
