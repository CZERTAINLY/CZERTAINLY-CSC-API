package com.czertainly.signserver.csc.model;

import com.czertainly.signserver.csc.api.OperationMode;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;

import java.util.List;

public record SignDocParameters(
        List<Document> documents, String credentialID, String signatureQualifier, SignatureActivationData sad,
        OperationMode operationMode, String clientData, boolean returnValidationInfo) {
}
