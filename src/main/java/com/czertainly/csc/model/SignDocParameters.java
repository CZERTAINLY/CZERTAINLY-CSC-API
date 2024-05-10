package com.czertainly.csc.model;

import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SignatureActivationData;

import java.util.List;

public record SignDocParameters(
        OperationMode operationMode,
        List<DocumentToSign> documentsToSign,
        List<DocumentDigestsToSign> documentDigestsToSign,
        String credentialID,
        String signatureQualifier,
        SignatureActivationData sad,
        String clientData,
        boolean returnValidationInfo) {
}
