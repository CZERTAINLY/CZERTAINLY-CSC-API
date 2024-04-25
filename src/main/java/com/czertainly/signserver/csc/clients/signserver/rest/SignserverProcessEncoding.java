package com.czertainly.signserver.csc.clients.signserver.rest;

public enum SignserverProcessEncoding {
    BASE64("BASE64"),
    NONE("NONE");

    private final String value;

    SignserverProcessEncoding(String value) {
        this.value = value;
    }

    public String toString() {
        return this.value;
    }
}
