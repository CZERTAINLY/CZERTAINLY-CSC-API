package com.otilm.csc.clients.signserver;

public record BatchSignatureWithValidationData(BatchSignaturesResponse signatureData, ValidationData validationData) {
}