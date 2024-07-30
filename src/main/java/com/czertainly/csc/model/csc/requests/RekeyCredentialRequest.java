package com.czertainly.csc.model.csc.requests;

import java.util.UUID;

public record RekeyCredentialRequest(
        UUID credentialID,
        String cryptoTokenName,

        String keyAlgorithm,
        String keySpecification,
        String csrSignatureAlgorithm
) {
}
