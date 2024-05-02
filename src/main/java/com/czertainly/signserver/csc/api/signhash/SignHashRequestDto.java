package com.czertainly.signserver.csc.api.signhash;

import com.czertainly.signserver.csc.api.BaseSignatureRequestDto;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Optional;

public class SignHashRequestDto extends BaseSignatureRequestDto {

    // One or more hash values to be signed. This parameter SHALL contain the Base64-encoded raw message digest(s).
    @Schema(
            description = """
                    An array containing the Base64-encoded raw message digest(s).
                    """,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private final List<String> hashes;

    /*
     * The OID of the algorithm used to calculate the hash value(s). This parameter SHALL be omitted or ignored
     * if the hash algorithm is implicitly specified by the signAlgo algorithm.
     * Only hashing algorithms as strong or stronger than SHA256 SHALL be used.
     */
    @Schema(
            description = """
                    Hashing algorithm OID used to calculate the hash value(s). This
                    parameter will be ignored if the hash algorithm is implicitly specified by the signAlgo algorithm.
                    """
    )
    private final String hashAlgorithmOID;

    // The OID of the algorithm to use for signing.
    @Schema(
            description = """
                    The OID of the algorithm to use for signing. If the parameter `hashAlgorithmOID` defined in
                    is passed, it must use the same algorithms as this parameter.
                    """,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private final String signAlgo;

    /*
     * The Base64-encoded DER-encoded ASN.1 signature parameters, if required by the signature algorithm.
     *  Some algorithms like RSASSA-PSS, as defined in RFC 8017 [18], may require additional parameters
     */
    @Schema(
            description = """
                    The Base64-encoded DER-encoded ASN.1 signature parameters, if required by
                    the `signAlgo`.
                    """
    )
    private final String signAlgoParams;

    public SignHashRequestDto(String credentialID, String SAD, List<String> hashes, String hashAlgorithmOID, String signAlgo,
                              String signAlgoParams, String operationMode, Integer validity_period, String response_uri,
                              String clientData
    ) {
        super(credentialID, SAD, operationMode, validity_period, response_uri, clientData);
        this.hashes = hashes;
        this.hashAlgorithmOID = hashAlgorithmOID;
        this.signAlgo = signAlgo;
        this.signAlgoParams = signAlgoParams;
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

}
