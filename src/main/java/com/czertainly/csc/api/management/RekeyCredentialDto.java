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
                    A name of the crypto token which will hold the generated private key for the credential.
                    
                    If not provided, the key will be stored in the same token as the old key.
                    """,
                example = "EntrustSAMCryptoToken",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String cryptoTokenName,

        @Schema(
                description = """
                    Key algorithm to use when generating new private key. The key algorithm must be supported by the
                    crypto token. See the documentation of the crypto token for supported key algorithms.
                    
                    If not provided, the key will be of the same algorithm as the old key.
                    """,
                example = "RSA",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String keyAlgorithm,

        @Schema(
                description = """
                    Key specification to use when generating new private keys. The key specification must be supported
                    by the crypto token. See the documentation of the crypto token for supported key specifications.
                    
                    If not provided, the key will be of the same specification as the old key.
                    """,
                example = "2048",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String keySpecification,

        @Schema(
                description = """
                    Signature algorithm the CSR will be signed with to request the certificate. The signature algorithm
                    must be supported by the crypto token. See the documentation of the crypto token for supported
                    signature algorithms.
                    
                    If not provided, the CSR will be signed with a default signature algorithm.
                    """,
                example = "SHA256withRSA",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String csrSignatureAlgorithm
) {

}
