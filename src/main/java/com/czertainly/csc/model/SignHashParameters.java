package com.czertainly.csc.model;

import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SignatureActivationData;

import java.util.List;

public record SignHashParameters(
        String userID,
        List<String> hashes,
        String keyAlgo,
        String digestAlgo,
        SignatureActivationData sad,
        OperationMode operationMode,
        String clientData
    ) {
}
