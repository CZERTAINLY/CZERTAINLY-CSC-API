package com.czertainly.signserver.csc.api.signdoc;

import com.czertainly.signserver.csc.api.BaseSignatureRequestDto;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Optional;

public class SignDocRequestDto extends BaseSignatureRequestDto {

    @Schema(
            description = """
                    Identifier of the signature type to be created. At least one of the two values
                    credentialID and signatureQualifier SHALL be present. Both values MAY be present.
                    """
    )
    private final String signatureQualifier;

    @Schema(
            description = """
                    An array containing document digest objects. This parameter or the
                    parameter `documents` MUST be present in a request.
                    """
    )
    private final List<DocumentDigestsDto> documentDigests;

    @Schema(
            description = """
                    An array containing document objects. This parameter or the
                    parameter `documentDigests` MUST be present in a request.
                    """
    )
    private final List<DocumentDto> documents;

    @Schema(
            description = """
                    If this parameter is present and set to `true` the server will return validation information in the response.
                    """,
            defaultValue = "false"
    )
    private final Boolean returnValidationInfo;


    public SignDocRequestDto(String credentialID, String signatureQualifier, String SAD, List<DocumentDto> documents,
                             List<DocumentDigestsDto> documentDigests, String operationMode, Integer validityPeriod,
                             String responseUri, String clientData, Boolean returnValidationInfo
    ) {
        super(credentialID, SAD, operationMode, validityPeriod, responseUri, clientData);
        this.signatureQualifier = signatureQualifier;
        this.documents = documents != null ? documents : List.of();
        this.documentDigests = documentDigests != null ? documentDigests : List.of();
        this.returnValidationInfo = returnValidationInfo;
    }

    public Optional<String> getSignatureQualifier() {
        return Optional.ofNullable(signatureQualifier);
    }

    public List<DocumentDto> getDocuments() {
        return documents;
    }

    public List<DocumentDigestsDto> getDocumentDigests() {
        return documentDigests;
    }


    public Optional<Boolean> getReturnValidationInfo() {
        return Optional.ofNullable(returnValidationInfo);
    }

}
