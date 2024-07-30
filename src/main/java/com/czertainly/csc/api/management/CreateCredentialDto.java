package com.czertainly.csc.api.management;

import com.czertainly.csc.model.csc.requests.CreateCredentialRequest;

public record CreateCredentialDto(

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
    public CreateCredentialRequest toModel() {
        return new CreateCredentialRequest(
                cryptoTokenName,
                keyAlgorithm,
                csrSignatureAlgorithm,
                keySpecification,
                userId,
                signatureQualifier,
                numberOfSignaturesPerAuthorization,
                scal,
                dn,
                san,
                description
        );
    }
}
