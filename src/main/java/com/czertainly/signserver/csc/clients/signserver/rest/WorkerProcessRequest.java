package com.czertainly.signserver.csc.clients.signserver.rest;

import java.util.Map;

public record WorkerProcessRequest(String data, Map<String, String> metaData, SignserverProcessEncoding encoding) {
}
