package com.otilm.csc.clients.signserver;

import java.util.List;

public record BatchSignatureRequests(List<BatchSignatureRequest> signatureRequests) {
}
