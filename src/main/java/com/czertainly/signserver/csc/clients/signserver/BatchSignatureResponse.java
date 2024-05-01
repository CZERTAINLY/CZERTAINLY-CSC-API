package com.czertainly.signserver.csc.clients.signserver;

public record BatchSignatureResponse(String signature, String hash, String customIdentifier) {
}
