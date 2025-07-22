package com.czertainly.csc.utils.signing;

import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentContentSignatureProcessConfiguration;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import static org.instancio.Select.field;

public class DocumentContentSignatureProcessConfigurationBuilder {

    InstancioClassApi<DocumentContentSignatureProcessConfiguration> partial = Instancio.of(
            DocumentContentSignatureProcessConfiguration.class);

    public static DocumentContentSignatureProcessConfiguration any() {
        return Instancio.of(DocumentContentSignatureProcessConfiguration.class)
                        .create();
    }

    public static DocumentContentSignatureProcessConfigurationBuilder instance() {
        return new DocumentContentSignatureProcessConfigurationBuilder();
    }

    public DocumentContentSignatureProcessConfigurationBuilder withUserID(String userID) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::userID), userID);
        return this;
    }

    public DocumentContentSignatureProcessConfigurationBuilder withSignatureQualifiers(String signatureQualifiers) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::signatureQualifier), signatureQualifiers);
        return this;
    }

    public DocumentContentSignatureProcessConfigurationBuilder withSignatureFormat(SignatureFormat signatureFormat) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::signatureFormat), signatureFormat);
        return this;
    }

    public DocumentContentSignatureProcessConfigurationBuilder withConformanceLevel(ConformanceLevel conformanceLevel) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::conformanceLevel), conformanceLevel);
        return this;
    }

    public DocumentContentSignatureProcessConfigurationBuilder withSignaturePackaging(
            SignaturePackaging signaturePackaging
    ) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::signaturePackaging), signaturePackaging);
        return this;
    }

    public DocumentContentSignatureProcessConfigurationBuilder withSignatureAlgorithm(
            SignatureAlgorithm signatureAlgorithm
    ) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::signatureAlgorithm), signatureAlgorithm);
        return this;
    }

    public DocumentContentSignatureProcessConfigurationBuilder withReturnValidationInfo(boolean returnValidationInfo) {
        partial.set(field(DocumentContentSignatureProcessConfiguration::returnValidationInfo), returnValidationInfo);
        return this;
    }

    public DocumentContentSignatureProcessConfiguration build() {
        return partial.create();
    }
}
