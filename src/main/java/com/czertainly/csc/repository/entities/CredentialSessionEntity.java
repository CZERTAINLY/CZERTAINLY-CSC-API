package com.czertainly.csc.repository.entities;

import com.czertainly.csc.service.credentials.CredentialSession;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@Table(name = "credential_sessions")
public class CredentialSessionEntity {
    @Id
    private UUID id;
    private UUID credentialId;
    private ZonedDateTime expiresIn;

    public CredentialSessionEntity() {
    }

    public CredentialSessionEntity(UUID id, UUID credentialId, ZonedDateTime expiresIn) {
        this.id = id;
        this.credentialId = credentialId;
        this.expiresIn = expiresIn;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(UUID credentialId) {
        this.credentialId = credentialId;
    }

    public ZonedDateTime getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(ZonedDateTime expiresIn) {
        this.expiresIn = expiresIn;
    }

    public static CredentialSessionEntity fromRecord(CredentialSession session) {
        return new CredentialSessionEntity(session.id(), session.credentialId(), session.getExpiresIn());
    }
}
