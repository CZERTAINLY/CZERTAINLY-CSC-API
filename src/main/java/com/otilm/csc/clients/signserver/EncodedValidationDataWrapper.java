package com.otilm.csc.clients.signserver;

public record EncodedValidationDataWrapper(String signatureData, ValidationData validationData) {
}