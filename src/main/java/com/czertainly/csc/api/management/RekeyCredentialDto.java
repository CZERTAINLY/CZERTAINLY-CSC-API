package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record RekeyCredentialDto(

        @Schema(
                description = """
                        Unique identifier of the credential to rekey.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID,

        @Schema(
                description = """
                        A name of the of the credential profile to use when generating the certificate.
                        """,
                example = "long-term",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialProfileName,

        @Schema(
                description = """
                        A name of the crypto token which will hold the generated private key for the credential.
                        
                        If not provided, the key will be stored in the same token as the old key.
                        """,
                example = "EntrustSAMCryptoToken",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String cryptoTokenName
) {

}
