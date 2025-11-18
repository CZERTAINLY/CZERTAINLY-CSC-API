package com.czertainly.csc.model.csc.requests;


public record CreateCredentialRequest(
        String cryptoTokenName,
        String credentialProfileName,
        String userId,
        String signatureQualifier,
        int numberOfSignaturesPerAuthorization,
        String scal,
        String dn,
        String san,
        String description,
        Boolean usePreGeneratedKey
) {
}
