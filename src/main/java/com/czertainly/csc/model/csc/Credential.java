package com.czertainly.csc.model.csc;

import java.util.Optional;

public record Credential(
        String credentialID,
        String description,
        Optional<String> signatureQualifier,
        KeyInfo key,
        CertificateInfo cert,
        int multisign
) {

}
