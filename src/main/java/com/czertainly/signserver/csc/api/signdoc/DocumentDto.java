package com.czertainly.signserver.csc.api.signdoc;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Optional;

public class DocumentDto extends BaseDocumentDto {

    // base64-encoded document content to be signed.
    @Schema(
            description = """
                    Base64-encoded document content to be signed.
                    """,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private final String document;

    public DocumentDto(String document, String signatureFormat, String conformanceLevel, String signAlgo,
                       String signAlgoParams, List<AttributeDto> signedAttributes, String signaturePackaging
    ) {
        super(signatureFormat, conformanceLevel, signAlgo, signAlgoParams, signedAttributes, signaturePackaging);
        this.document = document;
    }

    public Optional<String> getDocument() {
        return Optional.ofNullable(document);
    }

}
