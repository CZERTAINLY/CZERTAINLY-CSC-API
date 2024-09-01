package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;

public record CredentialIdDto(

        @Schema(
                description = """
                    Unique identifier of the credential.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID
) {
        public static CredentialIdDto from(UUID credentialID) {
                return new CredentialIdDto(credentialID.toString());
        }
}
