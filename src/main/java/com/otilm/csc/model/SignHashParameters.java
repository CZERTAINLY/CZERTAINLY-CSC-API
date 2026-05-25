package com.otilm.csc.model;

import com.otilm.csc.api.OperationMode;
import com.otilm.csc.api.auth.SignatureActivationData;
import com.otilm.csc.crypto.SignatureAlgorithm;

import java.util.List;
import java.util.UUID;

public record SignHashParameters(
        UUID credentialID,
        String userID,
        List<String> hashes,
        SignatureAlgorithm signatureAlgorithm,
        SignatureActivationData sad,
        OperationMode operationMode,
        String clientData
) {
}
