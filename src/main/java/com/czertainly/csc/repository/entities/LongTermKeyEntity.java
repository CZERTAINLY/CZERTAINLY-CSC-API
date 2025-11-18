package com.czertainly.csc.repository.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "long_term_keys")
public class LongTermKeyEntity {

    @Id
    UUID id;
    int cryptoTokenId;
    String keyAlias;
    String keyAlgorithm;

    public LongTermKeyEntity() {
    }

    public LongTermKeyEntity(UUID id, int cryptoTokenId, String keyAlias, String keyAlgorithm
    ) {
        this.id = id;
        this.cryptoTokenId = cryptoTokenId;
        this.keyAlias = keyAlias;
        this.keyAlgorithm = keyAlgorithm;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
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
}