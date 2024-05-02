package com.czertainly.signserver.csc.signing.configuration;

import java.util.Arrays;
import java.util.stream.Collectors;

public enum SignatureFormat {
    CAdES("C"),
    PAdES("P"),
    XAdES("X"),
    JAdEs("J");

    private final String value;

    SignatureFormat(String value) {
        this.value = value;
    }

    public static SignatureFormat fromString(String value) throws IllegalArgumentException {
        for (SignatureFormat format : SignatureFormat.values()) {
            if (format.value.equals(value)) {
                return format;
            }
        }

        throw new IllegalArgumentException(
                "Unknown signature format '" + value + "'. Allowed values: [" + Arrays.stream(
                        SignatureFormat.values()).map(cl -> cl.value).collect(
                        Collectors.joining(",")) + "]");
}

public String toString() {
    return this.value;
}
}
