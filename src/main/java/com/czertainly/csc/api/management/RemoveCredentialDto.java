package com.czertainly.csc.api.management;

import com.czertainly.csc.model.CertificateRevocationReason;
import io.swagger.v3.oas.annotations.media.Schema;

public record RemoveCredentialDto(
        @Schema(
                description = """
                        Unique identifier of the credential.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID,

        @Schema(
                description = """
                        Specifies the reason for revocation of the certificate.
                        If provided, the certificate will be revoked with the specified reason.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        CertificateRevocationReason revocationReason
) {
}
