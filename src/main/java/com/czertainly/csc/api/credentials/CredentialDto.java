package com.czertainly.csc.api.credentials;

import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.model.csc.Credential;
import io.swagger.v3.oas.annotations.media.Schema;

public record CredentialDto(

        @Schema(
                description = """
                        The credentialID identifying one of the credentials associated with the provided or implicit userID.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String credentialID,
        @Schema(
                description = """
                        A free form description of the credential in the lang language. The
                        maximum size of the string is 255 characters.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String description,

        @Schema(
                description = """
                        Identifier qualifying the type of signature this credential is suitable for
                        (see signatures/signDoc).
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String signatureQualifier,

        @Schema(
                description = """
                        Cryptographic key details.
                        """,
                implementation = KeyDto.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        KeyDto key,

        @Schema(
                description = """
                        Certificate details.
                        """,
                implementation = KeyDto.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        CertificateDto cert,

        @Schema(
                description = """
                        A number equal or higher to 1 representing the maximum number of
                        signatures that can be created with this credential with a single
                        authorization request (e.g. by calling credentials/signHash method, as
                        defined in signatures/signHash, once with multiple hash values or calling
                        it multiple times). The value of numSignatures specified in the
                        authorization request SHALL NOT exceed the value of this value.
                        """,
                implementation = KeyDto.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        int multisign,

        @Schema(
                description = """
                        Authorization details.
                        """,
                implementation = KeyDto.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        AuthDto authDto

        // TODO: l.najman - add lang param when it is clear, what the value should be
) {

    public static CredentialDto fromModel(Credential credential, DateConverter dateConverter) {
        return new CredentialDto(
                credential.credentialID(),
                credential.description(),
                credential.signatureQualifier().orElse(null),
                KeyDto.fromModel(credential.key()),
                CertificateDto.fromModel(credential.cert(), dateConverter),
                credential.multisign(),
                AuthDto.oauth2()
        );
    }

}
