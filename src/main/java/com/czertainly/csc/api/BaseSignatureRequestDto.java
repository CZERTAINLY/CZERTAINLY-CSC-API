package com.czertainly.csc.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Optional;

public class BaseSignatureRequestDto {

    @Schema(
            description = """
                    The unique identifier associated to the credential. At least one of the two values
                    credentialID and signatureQualifier SHALL be present. Both values MAY be present.
                    """
    )
    private final String credentialID;

    @Schema(
            description = """
                    The Signature Activation Data returned by the Credential Authorization
                    methods. Not needed if the signing application has passed an access token
                    with scope “credential” in the “Authorization” HTTP header, which is also
                    good for the credential identified by credentialID or the signature qualifier
                    identified by signatureQualifier.
                    """
    )
    private final String SAD;

    @Schema(
            description = """
                    The type of operation mode requested. Only the following is implemented:
                    - `S`: a synchronous operation mode is requested.
                    - `A`: an asynchronous operation mode is requested.
                    """,
            defaultValue = "S",
            implementation = OperationMode.class
    )
    private final String operationMode;

    /*
     * Maximum period of time, expressed in milliseconds, until which the server SHALL keep the request outcome(s)
     * available for the client application retrieval. This parameter MAY be specified only if the parameter
     * operationMode is “A”. If the parameter operationMode is not “A” and this parameter is specified its value
     * SHALL be ignored.
     * The RSSP SHOULD define in its service policy the default and maximum values of this parameter. If the RSSP
     * does not define in its service policy any default and maximum values of this parameter it means that any value
     * MAY be passed in this parameter.
     */
    @JsonProperty("validity_period")
    @Schema(
            description = """
                    Maximum period of time, expressed in milliseconds, until which the server keeps the request outcome(s)
                    available for retrieval. This parameter is for future updates and currently ignored in synchronous mode.
                    """
    )
    private final Integer validityPeriod;

    /*
     * Value of one location where the server will notify the signature creation operation completion, as a URI value.
     *  This parameter MAY be specified only if the parameter operationMode is “A”. If the parameter operationMode
     *  is not “A” and this parameter is specified its value SHALL be ignored. If the parameter operationMode is “A”
     *  and this parameter is omitted then the remote signing server will not make any notification.
     */
    @JsonProperty("response_uri")
    @Schema(
            description = """
                    Value of one location where the server will notify the signature creation operation completion, as a URI value.
                    This parameter is for future updates and currently ignored in synchronous mode.
                    """
    )
    private final String responseUri;

    @Schema(
            description = """
                    Arbitrary data from the client. It is used to handle a application-specific data that may be useful for
                    debugging purposes.
                    """
    )
    private final String clientData;

    public BaseSignatureRequestDto(String credentialID, String SAD, String operationMode, Integer validityPeriod,
                                   String responseUri, String clientData
    ) {
        this.credentialID = credentialID;
        this.SAD = SAD;
        this.operationMode = operationMode;
        this.validityPeriod = validityPeriod;
        this.responseUri = responseUri;
        this.clientData = clientData;
    }

    public Optional<String> getCredentialID() {
        return Optional.ofNullable(credentialID);
    }

    public Optional<String> getSAD() {
        return Optional.ofNullable(SAD);
    }

    public Optional<String> getOperationMode() {
        return Optional.ofNullable(operationMode);
    }

    public Optional<Integer> getValidityPeriod() {
        return Optional.ofNullable(validityPeriod);
    }

    public Optional<String> getResponseUri() {
        return Optional.ofNullable(responseUri);
    }

    public Optional<String> getClientData() {
        return Optional.ofNullable(clientData);
    }

}
