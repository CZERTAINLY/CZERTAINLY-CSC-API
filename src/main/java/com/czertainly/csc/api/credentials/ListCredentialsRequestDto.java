package com.czertainly.csc.api.credentials;

import io.swagger.v3.oas.annotations.media.Schema;

public record ListCredentialsRequestDto(

        @Schema(
                description = """
                        The identifier associated to the identity of the credential owner. This parameter
                        SHALL NOT be present if the service authorization is user-specific (see NOTE below).
                        In that case the userID is already implicit in the service access token passed in the
                        Authorization header.
                        If a user-specific service authorization is present, it SHALL NOT be allowed to use
                        this parameter to obtain the list of credentials associated to a different user. The
                        remote service SHALL return an error in such case.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String userID,

        @Schema(
                description = """
                        Request to return the main information included in the public key certificate and
                        the public key certificate itself or the certificate chain associated to the credentials.
                        The default value is “false”, so if the parameter is omitted then the information will
                        not be returned.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Boolean credentialInfo,

        @Schema(
                description = """
                        Specifies which certificates from the certificate chain SHALL be returned in
                        certs/certificates.
                        - “none”: No certificate SHALL be returned.
                        - “single”: Only the end entity certificate SHALL be returned.
                        - “chain”: The full certificate chain SHALL be returned.
                        The default value is “single”, so if the parameter is omitted then the method will
                        only return the end entity certificate(s).
                        This parameter MAY be specified only if the parameter credentialInfo is “true”. If
                        the parameter credentialInfo is not “true” and this parameter is specified its value
                        SHALL be ignored.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String certificates,
        @Schema(
                description = """
                        Request to return various parameters containing information from the end entity
                        certificate(s). This is useful in case the signature application wants to retrieve some
                        details of the certificate(s) without having to decode it first. The default value is
                        “false”, so if the parameter is omitted then the information will not be returned.
                        This parameter MAY be specified only if the parameter credentialInfo is “true”. If
                        the parameter credentialInfo is not “true” and this parameter is specified its value
                        SHALL be ignored.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Boolean certInfo,
        @Schema(
                description = """
                        Request to return various parameters containing information on the authorization
                        mechanisms supported by the corresponding credential (auth group). The default
                        value is “false”, so if the parameter is omitted then the information will not be
                        returned.
                        This parameter MAY be specified only if the parameter credentialInfo is “true”. If
                        the parameter credentialInfo is not “true” and this parameter is specified its value
                        SHALL be ignored.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Boolean authInfo,

        @Schema(
                description = """
                        Arbitrary data from the signature application. It can be used to handle a
                        transaction identifier or other application-specific data that may be useful for
                        debugging purposes. WARNING: this parameter MAY expose sensitive data to
                        the remote service. Therefore it SHOULD be used carefully.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String clientData,

        @Schema(
                description = """
                        Request to return only credentials usable to create a valid signature. The default
                        value is “false”, so if the parameter is omitted then the method will return all
                        credentials available to the owner.
                        The remote service MAY NOT support this parameter. When the parameter is
                        supported SHALL be returned in output.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        Boolean onlyValid
) {
}
