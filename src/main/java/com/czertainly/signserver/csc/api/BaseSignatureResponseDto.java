package com.czertainly.signserver.csc.api;

import io.swagger.v3.oas.annotations.media.Schema;

public class BaseSignatureResponseDto {

    @Schema(
            description = """
                        Arbitrary string value uniquely identifying the response. Returned only when operationMode is `A.`
                        """
    )
    private final String responseId;

    public BaseSignatureResponseDto(String responseId) {
        this.responseId = responseId;
    }

    public String getResponseId() {
        return responseId;
    }

}
