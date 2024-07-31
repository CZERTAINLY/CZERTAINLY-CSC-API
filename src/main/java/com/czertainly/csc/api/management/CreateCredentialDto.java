package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record CreateCredentialDto(

        @Schema(
                description = """
                    A name of the crypto token which will hold the new key.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String cryptoTokenName,

        @Schema(
                description = """
                    An algorithm of the new key, eg. `RSA` or `ECDSA`.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String keyAlgorithm,

        @Schema(
                description = """
                    A key specification of the new key.
                    For RSA keys, it is the key size in bits. For ECDSA keys, it is the curve name.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String keySpecification,

        @Schema(
                description = """
                    Signature Algorithm the CSR will be signed with, eg. `SHA256withRSA`.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String csrSignatureAlgorithm,

        @Schema(
                description = """
                    An ID of the user the credential will belong to.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String userId,

        @Schema(
                description = """
                    A qualifier of the signature, eg. `eu_eidas_aes`.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String signatureQualifier,

        @Schema(
                description = """
                    The number of signatures that can be made with the credential during a single authorization.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Integer numberOfSignaturesPerAuthorization,

        @Schema(
                description = """
                    A signature creation and verification level (SCAL) of the credential.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String scal,

        @Schema(
                description = """
                    A distinguished name (DN) of the credential. Will be used DN of the certificate.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String dn,

        @Schema(
                description = """
                    A subject alternative name (SAN) of the credential. Will be used SAN of the certificate.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String san,

        @Schema(
                description = """
                    A free text description of the credential.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String description
) {
}
