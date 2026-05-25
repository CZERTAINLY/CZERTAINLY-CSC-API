package com.otilm.csc.clients.signserver;

import java.util.List;

public record BatchSignaturesResponse(List<BatchSignatureResponse> signatures) {
}
