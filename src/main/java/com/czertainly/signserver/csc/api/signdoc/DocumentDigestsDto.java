package com.czertainly.signserver.csc.api.signdoc;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Optional;

public class DocumentDigestsDto extends BaseDocumentDto {

    // base64-encoded document hashes to be signed.
    @Schema(
            description = """
                    An array containing the Base64-encoded document hashes to be signed.
                    """,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private final List<String> hashes;

    @Schema(
            description = """
                    Hashing algorithm OID used to calculate document(s) hash(es). This
                    parameter will be ignored if the hash algorithm is implicitly specified by the signAlgo algorithm.
                    """
    )
    private final String hashAlgorithmOID;

    public DocumentDigestsDto(List<String> hashes, String hashAlgorithmOID, String signatureFormat,
                              String conformanceLevel, String signAlgo, String signAlgoParams,
                              List<AttributeDto> signedAttributes, String signaturePackaging
    ) {
        super(signatureFormat, conformanceLevel, signAlgo, signAlgoParams, signedAttributes, signaturePackaging);
        this.hashes = hashes;
        this.hashAlgorithmOID = hashAlgorithmOID;
    }

    public Optional<List<String>> getHashes() {
        return Optional.ofNullable(hashes);
    }

    public Optional<String> getHashAlgorithmOID() {
        return Optional.ofNullable(hashAlgorithmOID);
    }

}
