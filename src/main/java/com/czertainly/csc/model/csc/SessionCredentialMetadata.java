package com.czertainly.csc.model.csc;

import java.util.UUID;

public record SessionCredentialMetadata(
        UUID id,
        String keyAlias,
        UUID keyId,
        String endEntityName,
        int multisign
) {
}
