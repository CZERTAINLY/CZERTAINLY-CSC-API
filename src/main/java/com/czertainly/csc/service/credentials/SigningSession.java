package com.czertainly.csc.service.credentials;

import java.time.ZonedDateTime;
import java.util.StringJoiner;
import java.util.UUID;

public record SigningSession(UUID id, UUID credentialId, ZonedDateTime getExpiresIn,
                             CredentialSessionStatus status) {


    @Override
    public String toString() {
        return new StringJoiner(", ", SigningSession.class.getSimpleName() + "[", "]")
                .add("id=" + id)
                .add("credentialId=" + credentialId)
                .add("getExpiresIn=" + getExpiresIn)
                .add("status=" + status)
                .toString();
    }
}