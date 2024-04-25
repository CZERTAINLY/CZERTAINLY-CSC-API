package com.czertainly.signserver.csc.api.signdoc;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Optional;

public class SignDocRequestDto {

    // The unique identifier associated to the credential.
    // At least one of the two values credentialID and signatureQualifier SHALL be present. Both values MAY be present.
    private final String credentialID;

    // Identifier of the signature type to be created, e.g. eu_eidas_qes
    private final String signatureQualifier;

    // Not needed if the signing application has passed an access token in the “Authorization” HTTP header
    // with scope “credential”, which is also good for the credential identified by credentialID
    private final String SAD;

    // TODO add documentDigests

    private final List<DocumentDto> documentDtos;


    /*
     * The type of operation mode requested to the remote signing server. It SHALL take one of the following values:
     *      “A”: an asynchronous operation mode is requested.
     *      “S”: a synchronous operation mode is requested.
     * The default value is “S”, so if the parameter is omitted then the remote signing server will manage the request
     * in synchronous operation mode.
     */
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
    private final Integer validityPeriod;

    /*
     * Value of one location where the server will notify the signature creation operation completion, as a URI value.
     *  This parameter MAY be specified only if the parameter operationMode is “A”. If the parameter operationMode
     *  is not “A” and this parameter is specified its value SHALL be ignored. If the parameter operationMode is “A”
     *  and this parameter is omitted then the remote signing server will not make any notification.
     */
    @JsonProperty("response_uri")
    private final String responseUri;

    private final String clientData;

    private final Boolean returnValidationInfo;


    public SignDocRequestDto(String credentialID, String signatureQualifier, String SAD, List<DocumentDto> documentDtos,
                             String operationMode, Integer validityPeriod, String responseUri, String clientData,
                             Boolean returnValidationInfo
    ) {
        this.credentialID = credentialID;
        this.signatureQualifier = signatureQualifier;
        this.SAD = SAD;
        this.documentDtos = documentDtos;
        this.operationMode = operationMode;
        this.validityPeriod = validityPeriod;
        this.responseUri = responseUri;
        this.clientData = clientData;
        this.returnValidationInfo = returnValidationInfo;
    }

    public Optional<String> getCredentialID() {
        return Optional.ofNullable(credentialID);
    }

    public Optional<String> getSignatureQualifier() {
        return Optional.ofNullable(signatureQualifier);
    }

    public List<DocumentDto> getDocuments() {
        return documentDtos;
    }

    public Optional<String> getResponseUri() {
        return Optional.ofNullable(responseUri);
    }

    public Optional<Boolean> getReturnValidationInfo() {
        return Optional.ofNullable(returnValidationInfo);
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

    public Optional<String> getClientData() {
        return Optional.ofNullable(clientData);
    }
}
