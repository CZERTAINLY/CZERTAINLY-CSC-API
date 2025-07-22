package com.czertainly.csc.signing.configuration.process.configuration;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.DocumentType;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;

public class SignatureProcessConfiguration {

    private final String userID;
    private final SignatureActivationData sad;
    private final String signatureQualifier;
    private final SignatureFormat signatureFormat;
    private final ConformanceLevel conformanceLevel;
    private final SignaturePackaging signaturePackaging;
    private final SignatureAlgorithm signatureAlgorithm;
    private final boolean returnValidationInfo;
    private final DocumentType documentType;

    public SignatureProcessConfiguration(String userID, SignatureActivationData sad,
                                         String signatureQualifier, SignatureFormat signatureFormat,
                                         ConformanceLevel conformanceLevel, SignaturePackaging signaturePackaging,
                                         SignatureAlgorithm signatureAlgorithm, boolean returnValidationInfo,
                                         DocumentType documentType
    ) {
        this.userID = userID;
        this.sad = sad;
        this.signatureQualifier = signatureQualifier;
        this.signatureFormat = signatureFormat;
        this.conformanceLevel = conformanceLevel;
        this.signaturePackaging = signaturePackaging;
        this.signatureAlgorithm = signatureAlgorithm;
        this.returnValidationInfo = returnValidationInfo;
        this.documentType = documentType;
    }

    public String userID() {
        return userID;
    }

    public SignatureActivationData sad() {
        return sad;
    }

    public String signatureQualifier() {
        return signatureQualifier;
    }

    public SignatureFormat signatureFormat() {
        return signatureFormat;
    }

    public ConformanceLevel conformanceLevel() {
        return conformanceLevel;
    }

    public SignaturePackaging signaturePackaging() {
        return signaturePackaging;
    }

    public SignatureAlgorithm signatureAlgorithm() {
        return signatureAlgorithm;
    }

    public boolean returnValidationInfo() {
        return returnValidationInfo;
    }

    public DocumentType documentType() {
        return documentType;
    }
}
