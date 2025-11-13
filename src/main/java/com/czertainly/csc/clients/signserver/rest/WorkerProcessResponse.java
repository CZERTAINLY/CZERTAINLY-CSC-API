package com.czertainly.csc.clients.signserver.rest;

import java.util.Map;

public record WorkerProcessResponse(String data, String requestId, String archiveId, Map<String, String> metaData,
                                    String signerCertificate) {
}
