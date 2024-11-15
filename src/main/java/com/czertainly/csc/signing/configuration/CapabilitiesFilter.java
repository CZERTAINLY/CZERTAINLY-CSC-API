package com.czertainly.csc.signing.configuration;

import com.czertainly.csc.signing.filter.*;
import com.czertainly.csc.signing.filter.*;

import java.util.StringJoiner;

public class CapabilitiesFilter {

    private String signatureQualifier;
    private SignatureFormat signatureFormat;
    private ConformanceLevel conformanceLevel;
    private SignaturePackaging signaturePackaging;
    private String signatureAlgorithm;
    private String signatureAlgorithmParameters;
    private boolean returnValidationInfo;

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

    public CapabilitiesFilter withSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
        return this;
    }

    public CapabilitiesFilter withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public CapabilitiesFilter withSignatureAlgorithmParameters(String signatureParameters) {
        this.signatureAlgorithmParameters = signatureParameters;
        return this;
    }

    public CapabilitiesFilter withReturnValidationInfo(boolean returnValidationInfo) {
        this.returnValidationInfo = returnValidationInfo;
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

        if (signaturePackaging != null) {
            andCriterion.add(new SignaturePackagingCriterion(signaturePackaging));
        }

        if (signatureAlgorithm != null) {
            andCriterion.add(new SignatureAlgorithmCriterion(signatureAlgorithm));
        }

        if (signatureAlgorithmParameters != null) {
            andCriterion.add(new SignatureAlgorithmParametersCriterion(signatureAlgorithmParameters));
        }

        andCriterion.add(new ValidationInfoCriterion(returnValidationInfo));


        return andCriterion;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", CapabilitiesFilter.class.getSimpleName() + "[", "]")
                .add("signatureQualifier='" + signatureQualifier + "'")
                .add("signatureFormat=" + signatureFormat)
                .add("conformanceLevel=" + conformanceLevel)
                .add("signaturePackaging=" + signaturePackaging)
                .add("signatureAlgorithm='" + signatureAlgorithm + "'")
                .add("signatureAlgorithmParameters='" + signatureAlgorithmParameters + "'")
                .add("returnValidationInfo=" + returnValidationInfo)
                .toString();
    }
}
