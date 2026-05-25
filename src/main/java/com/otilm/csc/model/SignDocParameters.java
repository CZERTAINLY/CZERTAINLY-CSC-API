package com.otilm.csc.model;

import com.otilm.csc.api.OperationMode;
import com.otilm.csc.api.auth.SignatureActivationData;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public record SignDocParameters(
        String userID,
        OperationMode operationMode,
        List<DocumentContentToSign> documentsToSign,
        List<DocumentDigestsToSign> documentDigestsToSign,
        UUID credentialID,
        String signatureQualifier,
        SignatureActivationData sad,
        Optional<String> clientData,
        Optional<UUID> sessionId,
        boolean returnValidationInfo) {
}
