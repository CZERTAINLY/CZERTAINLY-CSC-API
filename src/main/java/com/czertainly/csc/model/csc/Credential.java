package com.czertainly.csc.model.csc;

public record Credential(
        String credentialID,
        String description,
        String signatureQualifier,
        KeyInfo key,
        CertificateInfo cert,
        int multisign
) {

}
