package com.czertainly.csc.api.credentials;

public record CredentialInfoDto(
        String credentialID,
        String certificates,
        Boolean certInfo,
        Boolean authInfo,
        String clientData
) {
}
