package com.czertainly.csc.clients.signserver;

public record BatchSignatureRequest(String data, String encryptionAlgorithm, String hashingAlgorithm, String customIdentifier) {
}
