package com.czertainly.csc.api.info;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record SignatureAlgorithmsDto(

        @Schema(description = """
                The list of signature algorithms supported by the remote service.
                """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> algos,

        @Schema(description = """
                The list of eventual signature parameters.
                """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        List<String> algoParams
) {
}
