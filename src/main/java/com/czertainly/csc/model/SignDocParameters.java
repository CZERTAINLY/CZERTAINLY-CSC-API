package com.czertainly.csc.model;

import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SignatureActivationData;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public record SignDocParameters(
        String userID,
        OperationMode operationMode,
        List<DocumentToSign> documentsToSign,
        List<DocumentDigestsToSign> documentDigestsToSign,
        UUID credentialID,
        String signatureQualifier,
        SignatureActivationData sad,
        Optional<String> clientData,
        Optional<UUID> sessionId,
        boolean returnValidationInfo) {
}
