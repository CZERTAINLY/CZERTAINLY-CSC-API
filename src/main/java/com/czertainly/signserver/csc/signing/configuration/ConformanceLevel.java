package com.czertainly.signserver.csc.signing.configuration;

import java.util.Arrays;
import java.util.stream.Collectors;

public enum ConformanceLevel {

    AdES_B_B("Ades-B-B"),
    AdES_B_T("Ades-B-T"),
    AdES_B_LT("Ades-B-LT"),
    AdES_B_LTA("Ades-B-LTA"),
    AdES_B("Ades-B"),
    AdES_T("Ades-T"),
    AdES_LT("Ades-LT"),
    AdES_LTA("Ades-LTA");


    private final String value;

    ConformanceLevel(String value) {
        this.value = value;
    }

    public static ConformanceLevel fromString(String value) throws IllegalArgumentException {
        for (ConformanceLevel level : ConformanceLevel.values()) {
            if (level.value.equals(value)) {
                return level;
            }
        }

        throw new IllegalArgumentException(
                "Unknown conformance level '" + value + "'. Allowed values: [" + Arrays.stream(
                        ConformanceLevel.values()).map(cl -> cl.value).collect(
                        Collectors.joining(",")) + "]");
    }

    public String toString() {
        return this.value;
    }

}
