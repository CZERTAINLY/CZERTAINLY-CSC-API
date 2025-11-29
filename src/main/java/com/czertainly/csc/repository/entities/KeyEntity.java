package com.czertainly.csc.repository.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;

import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
public abstract class KeyEntity {

    @Id
    UUID id;
    int cryptoTokenId;
    String keyAlias;
    String keyAlgorithm;
    Boolean inUse;
    ZonedDateTime acquiredAt;

    public KeyEntity() {
    }

    public KeyEntity(
            UUID id, int cryptoTokenId, String keyAlias, String keyAlgorithm, Boolean inUse, ZonedDateTime acquiredAt
    ) {
        this.id = id;
        this.cryptoTokenId = cryptoTokenId;
        this.keyAlias = keyAlias;
        this.keyAlgorithm = keyAlgorithm;
        this.inUse = inUse;
        this.acquiredAt = acquiredAt;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public int getCryptoTokenId() {
        return cryptoTokenId;
    }

    public void setCryptoTokenId(int cryptoTokenId) {
        this.cryptoTokenId = cryptoTokenId;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String key_algorithm) {
        this.keyAlgorithm = key_algorithm;
    }

    public Boolean getInUse() {
        return inUse;
    }

    public void setInUse(Boolean inUse) {
        this.inUse = inUse;
    }

    public ZonedDateTime getAcquiredAt() {
        return acquiredAt;
    }

    public void setAcquiredAt(ZonedDateTime acquiredAt) {
        this.acquiredAt = acquiredAt;
    }
}
