package com.czertainly.signserver.csc.api.common;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ErrorDto(String error, String errorDescription) {

    @Override
    @JsonProperty("error")
    public String error() {
        return error;
    }

    @Override
    @JsonProperty("error_description")
    public String errorDescription() {
        return errorDescription;
    }
}
