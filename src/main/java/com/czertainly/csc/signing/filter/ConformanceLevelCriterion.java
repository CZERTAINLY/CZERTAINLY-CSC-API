package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;

public class ConformanceLevelCriterion implements Criterion<WorkerCapabilities> {

    private final ConformanceLevel conformanceLevel;

    public ConformanceLevelCriterion(ConformanceLevel conformanceLevel) {
        this.conformanceLevel = conformanceLevel;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        return element.conformanceLevel().equals(conformanceLevel);
    }
}
