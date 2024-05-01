package com.czertainly.signserver.csc.clients.signserver;

public record BatchSignatureRequest(String data, String hashingAlgorithm, String customIdentifier) {
}
