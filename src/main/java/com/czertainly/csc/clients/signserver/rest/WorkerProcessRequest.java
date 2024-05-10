package com.czertainly.csc.clients.signserver.rest;

import java.util.Map;

public record WorkerProcessRequest(String data, Map<String, String> metaData, SignserverProcessEncoding encoding) {
}
