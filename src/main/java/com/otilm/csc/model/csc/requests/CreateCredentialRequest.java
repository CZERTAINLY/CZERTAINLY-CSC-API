package com.otilm.csc.model.csc.requests;


import com.otilm.csc.model.csc.CertificateReturnType;

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
        Boolean usePreGeneratedKey,
        CertificateReturnType certificateReturnType
) {
}
