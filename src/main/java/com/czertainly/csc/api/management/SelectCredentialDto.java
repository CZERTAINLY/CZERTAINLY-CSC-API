package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record SelectCredentialDto(
        @Schema(
                description = """
                        Unique identifier of the credential.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID
) {
}
