package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.signing.configuration.*;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.util.List;

import static org.instancio.Select.field;

public class WorkerCapabilitiesBuilder {

    InstancioClassApi<WorkerCapabilities> partial = Instancio.of(WorkerCapabilities.class);

    public static WorkerWithCapabilities any() {
        return Instancio.create(WorkerWithCapabilities.class);
    }

    public static WorkerCapabilitiesBuilder create() {
        return new WorkerCapabilitiesBuilder();
    }

    public WorkerCapabilitiesBuilder withSignatureQualifiers(List<String> signatureQualifiers) {
        partial.set(field(WorkerCapabilities::signatureQualifiers), signatureQualifiers);
        return this;
    }

    public WorkerCapabilitiesBuilder withSignatureFormat(SignatureFormat signatureFormat) {
        partial.set(field(WorkerCapabilities::signatureFormat), signatureFormat);
        return this;
    }

    public WorkerCapabilitiesBuilder withConformanceLevel(ConformanceLevel conformanceLevel) {
        partial.set(field(WorkerCapabilities::conformanceLevel), conformanceLevel);
        return this;
    }

    public WorkerCapabilitiesBuilder withSignaturePackaging(SignaturePackaging signaturePackaging) {
        partial.set(field(WorkerCapabilities::signaturePackaging), signaturePackaging);
        return this;
    }

    public WorkerCapabilitiesBuilder withSupportedSignatureAlgorithms(List<String> supportedSignatureAlgorithms) {
        partial.set(field(WorkerCapabilities::supportedSignatureAlgorithms), supportedSignatureAlgorithms);
        return this;
    }

    public WorkerCapabilitiesBuilder withReturnsValidationInfo(boolean returnsValidationInfo) {
        partial.set(field(WorkerCapabilities::returnsValidationInfo), returnsValidationInfo);
        return this;
    }

    public WorkerCapabilities build() {
        return partial.create();
    }

}
