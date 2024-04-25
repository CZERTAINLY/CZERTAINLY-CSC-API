package com.czertainly.signserver.csc.api.signhash;

import java.util.List;
import java.util.Optional;

public class SignHashRequestDto {

    // Not needed if the signing application has passed an access token in the “Authorization” HTTP header
    // with scope “credential”, which is also good for the credential identified by credentialID
    private final String SAD;

    // One or more hash values to be signed. This parameter SHALL contain the Base64-encoded raw message digest(s).
    private final List<String> hashes;

    /*
     * The OID of the algorithm used to calculate the hash value(s). This parameter SHALL be omitted or ignored
     * if the hash algorithm is implicitly specified by the signAlgo algorithm.
     * Only hashing algorithms as strong or stronger than SHA256 SHALL be used.
     */
    private final String hashAlgorithmOID;

    // The OID of the algorithm to use for signing.
    private final String signAlgo;

    /*
     * The Base64-encoded DER-encoded ASN.1 signature parameters, if required by the signature algorithm.
     *  Some algorithms like RSASSA-PSS, as defined in RFC 8017 [18], may require additional parameters
     */
    private final String signAlgoParams;


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
    private final Integer validity_period;

    /*
     * Value of one location where the server will notify the signature creation operation completion, as a URI value.
     *  This parameter MAY be specified only if the parameter operationMode is “A”. If the parameter operationMode
     *  is not “A” and this parameter is specified its value SHALL be ignored. If the parameter operationMode is “A”
     *  and this parameter is omitted then the remote signing server will not make any notification.
     */
    private final String response_uri;

    private final String clientData;


    public SignHashRequestDto(String SAD, List<String> hashes, String hashAlgorithmOID, String signAlgo,
                              String signAlgoParams, String operationMode, Integer validity_period, String response_uri,
                              String clientData
    ) {
        this.SAD = SAD;
        this.hashes = hashes;
        this.hashAlgorithmOID = hashAlgorithmOID;
        this.signAlgo = signAlgo;
        this.signAlgoParams = signAlgoParams;
        this.operationMode = operationMode;
        this.validity_period = validity_period;
        this.response_uri = response_uri;
        this.clientData = clientData;
    }

    public Optional<String> getSAD() {
        return Optional.ofNullable(SAD);
    }

    public Optional<List<String>> getHashes() {
        return Optional.ofNullable(hashes);
    }

    public String getHashAlgorithmOID() {
        return hashAlgorithmOID;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public Optional<String> getSignAlgoParams() {
        return Optional.ofNullable(signAlgoParams);
    }

    public Optional<String> getOperationMode() {
        return Optional.ofNullable(operationMode);
    }

    public Optional<Integer> getValidity_period() {
        return Optional.ofNullable(validity_period);
    }

    public Optional<String> getResponse_uri() {
        return Optional.ofNullable(response_uri);
    }

    public Optional<String> getClientData() {
        return Optional.ofNullable(clientData);
    }
}
