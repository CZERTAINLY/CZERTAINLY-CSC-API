package com.czertainly.signserver.csc.signing.configuration;

import java.util.Arrays;
import java.util.stream.Collectors;

public enum SignaturePackaging {

    ATTACHED("Attached"),
    DETACHED("Detached"),
    ENVELOPING("Enveloping"),
    ENVELOPED("Enveloped"),
    REVISION("Revision"),
    CERTIFICATION("Certification"),
    PARALLEL("Parallel");

    private final String value;

    SignaturePackaging(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static SignaturePackaging fromString(String value) {
        for (SignaturePackaging packaging : SignaturePackaging.values()) {
            if (packaging.value.equals(value)) {
                return packaging;
            }
        }
        throw new IllegalArgumentException("Unknown signature packaging: Allowed values: [" + Arrays.stream(
                SignaturePackaging.values()).map(cl -> cl.value).collect(
                Collectors.joining(",")) + "]");
    }
}
