package com.otilm.csc.api.common;

import com.otilm.csc.api.ErrorCode;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

public record ErrorDto(String error, String errorDescription) {

    @Override
    @JsonProperty("error")
    @Schema(
            description = "Error message",
            implementation = ErrorCode.class,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    public String error() {
        return error;
    }

    @Override
    @JsonProperty("error_description")
    @Schema(
            description = "Error description"
    )
    public String errorDescription() {
        return errorDescription;
    }
}
