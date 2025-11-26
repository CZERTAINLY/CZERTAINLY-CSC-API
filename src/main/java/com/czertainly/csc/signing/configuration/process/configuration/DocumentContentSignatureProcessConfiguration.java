package com.czertainly.csc.signing.configuration.process.configuration;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.DocumentType;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;

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
