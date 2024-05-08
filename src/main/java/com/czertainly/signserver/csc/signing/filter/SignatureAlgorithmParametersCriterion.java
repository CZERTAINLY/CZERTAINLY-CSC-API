package com.czertainly.signserver.csc.signing.filter;

import com.czertainly.signserver.csc.signing.configuration.WorkerCapabilities;

public class SignatureAlgorithmParametersCriterion implements Criterion<WorkerCapabilities> {

    private final String parameters;

    public SignatureAlgorithmParametersCriterion(String parameters) {
        this.parameters = parameters;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        // TODO: Implement matching logic
        return true;
    }
}
