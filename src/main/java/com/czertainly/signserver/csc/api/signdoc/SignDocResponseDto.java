package com.czertainly.signserver.csc.api.signdoc;

import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;

import java.util.Base64;
import java.util.List;

public record SignDocResponseDto(
        List<String> documentWithSignature,
        List<String> signatureObject,
        ValidationInfo validationInfo

) {
}
