package com.czertainly.csc.utils.signing;

import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import static org.instancio.Select.field;

public class DocumentHashSignatureProcessConfigurationBuilder {

    InstancioClassApi<DocumentHashSignatureProcessConfiguration> partial = Instancio.of(
            DocumentHashSignatureProcessConfiguration.class);

    public static DocumentHashSignatureProcessConfiguration any() {
        return Instancio.of(DocumentHashSignatureProcessConfiguration.class)
                        .create();
    }

    public static DocumentHashSignatureProcessConfigurationBuilder instance() {
        return new DocumentHashSignatureProcessConfigurationBuilder();
    }

    public DocumentHashSignatureProcessConfigurationBuilder withUserID(String userID) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::userID), userID);
        return this;
    }

    public DocumentHashSignatureProcessConfigurationBuilder withSignatureQualifiers(String signatureQualifiers) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::signatureQualifier), signatureQualifiers);
        return this;
    }

    public DocumentHashSignatureProcessConfigurationBuilder withSignatureFormat(SignatureFormat signatureFormat) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::signatureFormat), signatureFormat);
        return this;
    }

    public DocumentHashSignatureProcessConfigurationBuilder withConformanceLevel(ConformanceLevel conformanceLevel) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::conformanceLevel), conformanceLevel);
        return this;
    }

    public DocumentHashSignatureProcessConfigurationBuilder withSignaturePackaging(
            SignaturePackaging signaturePackaging
    ) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::signaturePackaging), signaturePackaging);
        return this;
    }

    public DocumentHashSignatureProcessConfigurationBuilder withSignatureAlgorithm(
            SignatureAlgorithm signatureAlgorithm
    ) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::signatureAlgorithm), signatureAlgorithm);
        return this;
    }

    public DocumentHashSignatureProcessConfigurationBuilder withReturnValidationInfo(boolean returnValidationInfo) {
        partial.set(field(DocumentHashSignatureProcessConfiguration::returnValidationInfo), returnValidationInfo);
        return this;
    }

    public DocumentHashSignatureProcessConfiguration build() {
        return partial.create();
    }
}
