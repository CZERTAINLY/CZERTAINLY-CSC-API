package com.czertainly.csc.api.management;

import io.swagger.v3.oas.annotations.media.Schema;

public record CreateCredentialDto(

        @Schema(
                description = """
                    A name of the crypto token which will hold the generated private key for the credential.
                    """,
                example = "EntrustSAMCryptoToken",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String cryptoTokenName,

        @Schema(
                description = """
                    Key algorithm to use when generating new private key. The key algorithm must be supported by the
                    crypto token. See the documentation of the crypto token for supported key algorithms.
                    """,
                example = "RSA",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String keyAlgorithm,

        @Schema(
                description = """
                    Key specification to use when generating new private keys. The key specification must be supported
                    by the crypto token. See the documentation of the crypto token for supported key specifications.
                    """,
                example = "2048",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String keySpecification,

        @Schema(
                description = """
                    Signature algorithm the CSR will be signed with to request the certificate. The signature algorithm
                    must be supported by the crypto token. See the documentation of the crypto token for supported
                    signature algorithms.
                    """,
                example = "SHA256withRSA",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String csrSignatureAlgorithm,

        @Schema(
                description = """
                    Identifier of the user the credential will belong to.
                    This identifier must be unique within the identity provider.
                    """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String userId,

        @Schema(
                description = """
                    Identifier qualifying the type of signature this credential is suitable for.
                    See the list of supported signature qualifiers in the CSC API specification.
                    """,
                example = "eu_eidas_qes",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String signatureQualifier,

        @Schema(
                description = """
                    Maximum number of signatures that can be created with this credential with a single
                    authorization request.
                    """,
                example = "2",
                defaultValue = "1",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Integer numberOfSignaturesPerAuthorization,

        @Schema(
                description = """
                    Specifies if the credential should generate a signature activation data (SAD) or an access token
                    with scope `credential` that contains a link to the hash to-be-signed:
                    - `1`: The hash to-be-signed is not linked to the signature activation data.
                    - `2`: The hash to-be-signed is linked to the signature activation data.
                    """,
                example = "1",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String scal,

        @Schema(
                description = """
                    A subject distinguished name (DN) of the credential for the certificate.
                    The format of the DN must be according to the X.500 standard. This field should contain
                    comma-separated key-value pairs, where the key is the type of the DN and the value is the
                    value of the DN.
                    """,
                example = "CN=John Doe,OU=IT,O=Company",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String dn,

        @Schema(
                description = """
                    A subject alternative name (SAN) of the credential for the certificate.
                    The format of the SAN must be according to the X.500 standard. This field should contain
                    comma-separated key-value pairs, where the key is the type of the SAN and the value is the
                    value of the SAN.
                    """,
                example = "rfc822Name=your.name@email.com",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String san,

        @Schema(
                description = """
                    A free form description of the credential in the lang language. The maximum size of the string
                    is 255 characters.
                    """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String description
) {
}
