package com.czertainly.csc.signing.configuration.loader;

import com.czertainly.csc.signing.configuration.DocumentType;

import java.util.Collections;
import java.util.List;

public class WorkerCapabilitiesConfiguration{
        private List<String> signatureQualifiers;
        private String signatureFormat;
        private String conformanceLevel;
        private String signaturePackaging;
        private List<String> signatureAlgorithms;
        private boolean returnsValidationInfo = false;
        private List<DocumentType> documentTypes;

    public List<String> getSignatureQualifiers() {
        return signatureQualifiers;
    }

    public void setSignatureQualifiers(List<String> signatureQualifiers) {
        this.signatureQualifiers = signatureQualifiers;
    }

    public String getSignatureFormat() {
        return signatureFormat;
    }

    public void setSignatureFormat(String signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    public String getConformanceLevel() {
        return conformanceLevel;
    }

    public void setConformanceLevel(String conformanceLevel) {
        this.conformanceLevel = conformanceLevel;
    }

    public String getSignaturePackaging() {
        return signaturePackaging;
    }

    public void setSignaturePackaging(String signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    public List<String> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    public void setSignatureAlgorithms(List<String> signatureAlgorithms) {
        this.signatureAlgorithms = signatureAlgorithms;
    }

    public boolean isReturnsValidationInfo() {
        return returnsValidationInfo;
    }

    public void setReturnsValidationInfo(boolean returnsValidationInfo) {
        this.returnsValidationInfo = returnsValidationInfo;
    }

    public List<DocumentType> getDocumentTypes() {
        // Default to HASH if not specified
        if (documentTypes == null || documentTypes.isEmpty()) {
            return Collections.singletonList(DocumentType.HASH);
        }
        return documentTypes;
    }

    public void setDocumentTypes(List<DocumentType> documentTypes) {
        this.documentTypes = documentTypes;
    }
}
