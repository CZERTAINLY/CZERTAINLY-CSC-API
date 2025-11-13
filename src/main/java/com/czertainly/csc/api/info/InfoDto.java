package com.czertainly.csc.api.info;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record InfoDto(
        @Schema(
                description = """
                        The version of this specification implemented by the provider. The
                        format of the string is Major.Minor.x.y , where Major is a number
                        equivalent to the API version (e.g. 2 for API v2) and Minor is a
                        number identifying the version update, while x and y are subversion
                        numbers.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String specs,

        @Schema(
                description = """
                        The commercial name of the remote service. The maximum size of
                        the string is 255 characters.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String name,

        @Schema(
                description = """
                        The URI of the image file containing the logo of the remote service
                        which SHALL be published online. The image SHALL be in either
                        JPEG or PNG format and not larger than 256x256 pixels.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String logo,

        @Schema(
                description = """
                        The ISO 3166-1 [22] Alpha-2 code of the Country where the remote
                        service provider is established (e.g. ES for Spain).
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String region,

        @Schema(
                description = """
                        The language used in the responses, specified according to RFC 5646.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String lang,

        @Schema(
                description = """
                        One or more values corresponding to the service authorization
                        mechanisms supported by the remote service to authorize the
                        access to the API:
                        - `external`: in case the authorization is managed externally (e.g. using a VPN or a private LAN).
                        - `TLS`: in case the authorization is provided by means of TLS client certificate authentication.
                        - `basic`: in case of HTTP Basic Authentication.
                        - `digest`: in case of HTTP Digest Authentication.
                        - `oauth2code`: in case of OAuth 2.0 with authorization code flow.
                        - `oauth2client`: in case of OAuth 2.0 with client credentials flow.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> authType,

        @Schema(
                description = """
                        The base URI of the OAuth 2.0 authorization server endpoint
                        supported by the remote service for service authorization and/or
                        credential authorization.
                        The parameter is present if
                        - the authType parameter contains “oauth2code” or “oauth2client” or
                        - the remote service supports the value “oauth2code” for the
                          auth/mode parameter returned by credentials/info
                        and the parameter “oauth2Issuer” is not present.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String oauth2,

        @Schema(
                description = """
                        The issuer URL of the OAuth 2.0 authorization server as defined in
                        IETF RFC 8414 supported by the remote service for service
                        authorization and/or credential authorization. The parameter
                        SHALL be present if
                        - the authType parameter contains “oauth2code” or “oauth2client” or
                        - the remote service supports the value “oauth2code” for the auth/mode
                          parameter returned by credentials/info
                        and the parameter “oauth2” is not present.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        String oauth2Issuer,

        @Schema(
                description = """
                        This parameter is “true” if the remote signing server supports
                        also asynchronous signature mechanism. The default value is
                        “false”. An omitted parameter or the value “false” indicates that the
                        remote signing server manages signature requests only in
                        synchronous operation mode
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        boolean asynchronousOperationMode,

        @Schema(
                description = """
                        The list of names of all the API methods described in this
                        specification that are implemented and supported by the remote
                        service.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> methods,

        @Schema(
                description = """
                        This parameter is “true” if the remote signing server
                        supports the “validationInfo” response parameter of the method
                        signatures/signDoc in not mandatory cases. An omitted parameter
                        or the value “false” indicates that the remote signing server does
                        not support “validationInfo” in those cases.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        boolean validationInfo,

        @Schema(
                description = """
                        Object including one or more signature algorithms supported by
                        the remote service.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        SignatureAlgorithmsDto signAlgorithms,

        @Schema(
                description = """
                        Object including one or more signature formats supported by the
                        remote service.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @JsonProperty("signature_formats")
        SignatureFormatsDto signatureFormats,

        @Schema(
                description = """
                        The list of names of all signature conformance levels supported by
                        the remote service.
                        """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> conformanceLevels
) {

}
