package com.czertainly.csc.model.csc;

import java.util.Optional;
import java.util.UUID;

public record CredentialMetadata(
        UUID id,
        String userId,
        String keyAlias,
        String credentialProfileName,
        Optional<String> signatureQualifier,
        int multisign,
        Optional<String> scal,
        String cryptoTokenName,
        boolean disabled
) {
}
