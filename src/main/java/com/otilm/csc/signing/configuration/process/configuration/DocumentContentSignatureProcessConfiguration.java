package com.otilm.csc.signing.configuration.process.configuration;

import com.otilm.csc.api.auth.SignatureActivationData;
import com.otilm.csc.crypto.SignatureAlgorithm;
import com.otilm.csc.signing.configuration.ConformanceLevel;
import com.otilm.csc.signing.configuration.DocumentType;
import com.otilm.csc.signing.configuration.SignatureFormat;
import com.otilm.csc.signing.configuration.SignaturePackaging;

public class DocumentContentSignatureProcessConfiguration extends SignatureProcessConfiguration {

    public DocumentContentSignatureProcessConfiguration(
            String userID, SignatureActivationData sad,
            String signatureQualifier, SignatureFormat signatureFormat,
            ConformanceLevel conformanceLevel,
            SignaturePackaging signaturePackaging, SignatureAlgorithm signatureAlgorithm,
            boolean returnValidationInfo
    ) {
        super(userID, sad, signatureQualifier, signatureFormat, conformanceLevel, signaturePackaging,
              signatureAlgorithm, returnValidationInfo, DocumentType.FULL
        );
    }
}
