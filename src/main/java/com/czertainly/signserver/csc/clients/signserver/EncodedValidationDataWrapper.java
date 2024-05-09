package com.czertainly.signserver.csc.clients.signserver;

public record EncodedValidationDataWrapper(String signatureData, ValidationData validationData) {
}