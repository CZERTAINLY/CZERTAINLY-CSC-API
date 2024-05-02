package com.czertainly.signserver.csc.api;

import com.czertainly.signserver.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.signserver.csc.signing.configuration.SignatureFormat;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.stream.Collectors;

public enum OperationMode {
    ASYNCHRONOUS("A"),
    SYNCHRONOUS("S");

    private final String value;

    OperationMode(String code) {
        this.value = code;
    }

    @JsonValue
    public String getValue() {
        return this.value;
    }

    @JsonCreator
    public static OperationMode findByCode(String value) {
        return Arrays.stream(OperationMode.values())
                .filter(k -> k.value.equals(value))
                .findFirst()
                .orElseThrow(() ->
                    new IllegalArgumentException(
                            "Unknown operation mode '" + value + "'. Allowed values: [" + Arrays.stream(
                                    OperationMode.values()).map(cl -> cl.value).collect(
                                            Collectors.joining(",")) + "]"));
    }

}
