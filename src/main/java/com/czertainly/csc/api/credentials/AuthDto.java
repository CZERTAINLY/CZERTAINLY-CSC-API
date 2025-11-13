package com.czertainly.csc.api.credentials;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record AuthDto(

        @Schema(
                description = """
                        Specifies one of the authorization modes.
                        “explicit”: the authorization process is managed by the signature
                        application, which collects authentication factors of various
                        types.
                        “oauth2code”: the authorization process is managed by the
                        remote service using an OAuth 2.0 mechanism.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String mode,

        @Schema(
                description = """
                        An expression defining the combination of authentication objects
                        required to authorize usage of the private key.
                        If empty, an “AND” of all authentication objects is implied.
                        Supported operators are: “AND” | “OR” | “XOR” | “(” | “)” This value
                        SHALL NOT be returned if auth/mode is not “explicit”.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        String expression,

        @Schema(
                description = """
                        The authentication object types available for this credential.
                        This value SHALL only be returned if auth/mode is “explicit”.
                        """,
                implementation = List.class,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        List<String> objects
) {

    public static AuthDto oauth2() {
        return new AuthDto("oauth2code", null, null);
    }

}
