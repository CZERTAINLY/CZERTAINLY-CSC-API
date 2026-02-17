package com.czertainly.csc.utils.signing.process;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.crypto.AlgorithmHelper;
import com.czertainly.csc.crypto.KeyAndHashSigAlgo;
import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.DocumentType;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.instancio.Instancio;

import static org.instancio.Select.field;

public class TestSignatureProcessConfiguration extends SignatureProcessConfiguration {

    private static final SignatureAlgorithm DEFAULT_SIGNATURE_ALGORITHM = KeyAndHashSigAlgo.of(
            new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"),  // RSA
            new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), // SHA-256
            new AlgorithmHelper()
    );

    public static TestSignatureProcessConfiguration any() {
        return Instancio.of(TestSignatureProcessConfiguration.class)
                        .set(field(SignatureProcessConfiguration.class, "signatureAlgorithm"), DEFAULT_SIGNATURE_ALGORITHM)
                        .create();
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
              signatureAlgorithm, returnValidationInfo, documentType
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