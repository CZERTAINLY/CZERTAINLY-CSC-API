package com.czertainly.csc.model.csc;

import com.czertainly.csc.service.credentials.CredentialSession;

import java.util.UUID;

public record SessionCredentialMetadata(
        CredentialSession session,
        String keyAlias,
        String endEntityName,
        int multisign
) {
}
