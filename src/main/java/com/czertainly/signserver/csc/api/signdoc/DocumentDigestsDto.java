package com.czertainly.signserver.csc.api.signdoc;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Optional;

public class DocumentDigestsDto {

    // base64-encoded document hashes to be signed.
    private final List<String> hashes;

    private final String hashAlgorithmOID;

    @JsonProperty("signature_format")
    private final String signatureFormat;

    @JsonProperty("conformance_level")
    private final String conformanceLevel;

    private final String signAlgo;

    private final String signAlgoParams;

    @JsonProperty("signed_props")
    private final List<AttributeDto> signedAttributes;

    @JsonProperty("signed_envelope_property")
    private final String signaturePackaging;


    public DocumentDigestsDto(List<String> hashes, String hashAlgorithmOID, String signatureFormat,
                              String conformanceLevel, String signAlgo, String signAlgoParams,
                              List<AttributeDto> signedAttributes, String signaturePackaging
    ) {
        this.hashes = hashes;
        this.hashAlgorithmOID = hashAlgorithmOID;
        this.signatureFormat = signatureFormat;
        this.conformanceLevel = conformanceLevel;
        this.signAlgo = signAlgo;
        this.signAlgoParams = signAlgoParams;
        this.signedAttributes = signedAttributes == null ? List.of() : signedAttributes;
        this.signaturePackaging = signaturePackaging;
    }

    public Optional<List<String>> getHashes() {
        return Optional.ofNullable(hashes);
    }

    public Optional<String> getHashAlgorithmOID() {
        return Optional.ofNullable(hashAlgorithmOID);
    }

    public Optional<String> getSignatureFormat() {
        return Optional.ofNullable(signatureFormat);
    }

    public Optional<String> getConformanceLevel() {
        return Optional.ofNullable(conformanceLevel);
    }

    public Optional<String> getSignAlgo() {
        return Optional.ofNullable(signAlgo);
    }

    public Optional<String> getSignAlgoParams() {
        return Optional.ofNullable(signAlgoParams);
    }

    public List<AttributeDto> getSignedAttributes() {
        return signedAttributes;
    }

    public Optional<String> getSignaturePackaging() {
        return Optional.ofNullable(signaturePackaging);
    }
}
