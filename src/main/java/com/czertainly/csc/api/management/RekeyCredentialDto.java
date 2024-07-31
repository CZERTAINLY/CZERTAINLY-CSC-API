package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record RekeyCredentialDto(

        @Schema(
                description = """
                    The ID of the credential to be rekeyed.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID,

        @Schema(
                description = """
                    A name of the crypto token which will hold the new key.
                    If not provided, the key will be stored in the same token as the old key.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String cryptoTokenName,

        @Schema(
                description = """
                    An algorithm of the new key, eg. `RSA` or `ECDSA`.
                    If not provided, the key will be of the same algorithm as the old key.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String keyAlgorithm,

        @Schema(
                description = """
                    A key specification of the new key.
                    For RSA keys, it is the key size in bits. For ECDSA keys, it is the curve name.
                    If not provided, the key will be of the same specification as the old key.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String keySpecification,

        @Schema(
                description = """
                    Signature Algorithm the CSR will be signed with, eg. `SHA256withRSA`.
                    If not provided, the CSR will be signed with a default signature algorithm.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String csrSignatureAlgorithm
) {

}
