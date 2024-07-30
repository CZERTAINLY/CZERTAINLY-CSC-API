package com.czertainly.csc.model.csc.requests;

public record CreateCredentialRequest(
        String cryptoTokenName,

        String keyAlgorithm,
        String csrSignatureAlgorithm,
        String keySpecification,
        String userId,
        String signatureQualifier,
        int numberOfSignaturesPerAuthorization,
        String scal,
        String dn,
        String san,
        String description
) {
}
