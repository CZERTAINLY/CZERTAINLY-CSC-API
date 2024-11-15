package com.czertainly.csc.api.common;

public class StructuredClientDataDto {
        private final String sessionId;
        private final String clientData;

    public StructuredClientDataDto(String sessionId, String clientData) {
        this.sessionId = sessionId;
        this.clientData = clientData;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientData() {
        return clientData;
    }
}
