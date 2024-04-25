package com.czertainly.signserver.csc.api.signdoc;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Optional;

public class DocumentDto {

    // base64-encoded document content to be signed.
    private final String document;

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


    public DocumentDto(String document, String signatureFormat, String conformanceLevel, String signAlgo,
                       String signAlgoParams, List<AttributeDto> signedAttributes, String signaturePackaging
    ) {
        this.document = document;
        this.signatureFormat = signatureFormat;
        this.conformanceLevel = conformanceLevel;
        this.signAlgo = signAlgo;
        this.signAlgoParams = signAlgoParams;
        this.signedAttributes =  signedAttributes == null ? List.of() : signedAttributes;
        this.signaturePackaging = signaturePackaging;
    }

    public Optional<String> getDocument() {
        return Optional.ofNullable(document);
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
