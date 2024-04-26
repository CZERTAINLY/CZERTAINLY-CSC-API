package com.czertainly.signserver.csc.model;

import com.czertainly.signserver.csc.api.OperationMode;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;

import java.util.List;

public record SignHashParameters(
        List<String> hashes, String keyAlgo, String digestAlgo, SignatureActivationData sad,
        OperationMode operationMode, String clientData) {
}
