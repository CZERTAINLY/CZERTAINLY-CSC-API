package com.czertainly.csc.utils.signing.process;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.DocumentType;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import org.instancio.Instancio;

public class TestSignatureProcessConfiguration extends SignatureProcessConfiguration {

    public static TestSignatureProcessConfiguration any() {
        return Instancio.create(TestSignatureProcessConfiguration.class);
    }

    public TestSignatureProcessConfiguration(String userID,
                                             SignatureActivationData sad,
                                             String signatureQualifier,
                                             SignatureFormat signatureFormat,
                                             ConformanceLevel conformanceLevel,
                                             SignaturePackaging signaturePackaging,
                                             SignatureAlgorithm signatureAlgorithm,
                                             boolean returnValidationInfo,
                                             DocumentType documentType
    ) {
        super(userID, sad, signatureQualifier, signatureFormat, conformanceLevel, signaturePackaging,
                signatureAlgorithm, returnValidationInfo, DocumentType.HASH
        );
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String userID;
        private SignatureActivationData sad;
        private String signatureQualifier;
        private SignatureFormat signatureFormat;
        private ConformanceLevel conformanceLevel;
        private SignaturePackaging signaturePackaging;
        private SignatureAlgorithm signatureAlgorithm;
        private boolean returnValidationInfo;
        private DocumentType documentType;

        public Builder withUserID(String userID) {
            this.userID = userID;
            return this;
        }

        public Builder withSad(SignatureActivationData sad) {
            this.sad = sad;
            return this;
        }

        public Builder withSignatureQualifier(String signatureQualifier) {
            this.signatureQualifier = signatureQualifier;
            return this;
        }

        public Builder withSignatureFormat(SignatureFormat signatureFormat) {
            this.signatureFormat = signatureFormat;
            return this;
        }

        public Builder withConformanceLevel(ConformanceLevel conformanceLevel) {
            this.conformanceLevel = conformanceLevel;
            return this;
        }

        public Builder withSignaturePackaging(SignaturePackaging signaturePackaging) {
            this.signaturePackaging = signaturePackaging;
            return this;
        }

        public Builder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        public Builder withReturnValidationInfo(boolean returnValidationInfo) {
            this.returnValidationInfo = returnValidationInfo;
            return this;
        }

        public Builder withDocumentType(DocumentType documentType) {
            this.documentType = documentType;
            return this;
        }

        public TestSignatureProcessConfiguration build() {
            return new TestSignatureProcessConfiguration(userID, sad, signatureQualifier, signatureFormat,
                                                         conformanceLevel, signaturePackaging, signatureAlgorithm,
                                                         returnValidationInfo, documentType
            );
        }
    }
}