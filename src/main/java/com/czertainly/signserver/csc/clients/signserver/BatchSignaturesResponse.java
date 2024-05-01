package com.czertainly.signserver.csc.clients.signserver;

import java.util.List;

public record BatchSignaturesResponse(List<BatchSignatureResponse> signatures) {
}
