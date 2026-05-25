package com.otilm.csc.model.csc.requests;

import java.util.UUID;

public record RekeyCredentialRequest(
        UUID credentialID,
        String credentialProfileName,
        String cryptoTokenName
) {
}
