package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record CredentialIdDto(

        @Schema(
                description = """
                    The ID uniquely identifying the credential.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID
) {
}
