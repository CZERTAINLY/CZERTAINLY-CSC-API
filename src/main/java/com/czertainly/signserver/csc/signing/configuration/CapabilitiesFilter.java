package com.czertainly.signserver.csc.signing.configuration;

import com.czertainly.signserver.csc.signing.filter.*;

public class CapabilitiesFilter {

    private String signatureQualifier;
    private SignatureFormat signatureFormat;
    private ConformanceLevel conformanceLevel;

    public static CapabilitiesFilter configure() {
        return new CapabilitiesFilter();
    }

    public CapabilitiesFilter withSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
        return this;
    }

    public CapabilitiesFilter withSignatureFormat(SignatureFormat signatureFormat) {
        this.signatureFormat = signatureFormat;
        return this;
    }

    public CapabilitiesFilter withConformanceLevel(ConformanceLevel conformanceLevel) {
        this.conformanceLevel = conformanceLevel;
        return this;
    }

    public Criterion<WorkerCapabilities> build() {
        var andCriterion = new AndCriterion<WorkerCapabilities>();
        if (signatureQualifier != null) {
            andCriterion.add(new SignatureQualifierCriterion(signatureQualifier));
        }

        if (signatureFormat != null) {
            andCriterion.add(new SignatureFormatCriterion(signatureFormat));
        }

        if (conformanceLevel != null) {
            andCriterion.add(new ConformanceLevelCriterion(conformanceLevel));
        }
        return andCriterion;
    }
}
