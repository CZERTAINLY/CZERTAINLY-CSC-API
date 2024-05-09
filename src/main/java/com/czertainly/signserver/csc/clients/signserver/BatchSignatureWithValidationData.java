package com.czertainly.signserver.csc.clients.signserver;

public record BatchSignatureWithValidationData(BatchSignaturesResponse signatureData, ValidationData validationData) {
}