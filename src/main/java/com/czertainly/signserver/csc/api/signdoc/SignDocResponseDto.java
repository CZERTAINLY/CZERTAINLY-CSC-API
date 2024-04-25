package com.czertainly.signserver.csc.api.signdoc;

import java.util.List;

public record SignDocResponseDto(
        List<String> documentWithSignature,
        List<String> signatureObject,
        ValidationInfo validationInfo
) {
}
