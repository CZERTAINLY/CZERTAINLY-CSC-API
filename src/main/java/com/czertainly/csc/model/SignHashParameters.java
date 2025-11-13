package com.czertainly.csc.model;

import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.crypto.SignatureAlgorithm;

import java.util.List;
import java.util.UUID;

public record SignHashParameters(
        UUID credentialID,
        String userID,
        List<String> hashes,
        String keyAlgo,
        String digestAlgo,
        SignatureActivationData sad,
        OperationMode operationMode,
        String clientData
) {
    public SignatureAlgorithm signatureAlgorithm() {
        return SignatureAlgorithm.of(keyAlgo, digestAlgo);
    }
}
