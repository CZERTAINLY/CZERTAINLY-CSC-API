package com.czertainly.csc.model.csc;

import java.util.UUID;

public record CredentialMetadata(
        UUID id,
        String userId,
        String keyAlias,
        String signatureQualifier,
        int multisign,
        String scal,
        String cryptoTokenName,
        boolean disabled
) {
}
