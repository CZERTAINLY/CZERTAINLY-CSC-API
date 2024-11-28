package com.czertainly.csc.repository.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@Table(name = "session_keys")
public class SessionKeyEntity extends KeyEntity {

    public SessionKeyEntity() {
    }

    public SessionKeyEntity(UUID id, int cryptoTokenId, String keyAlias, String keyAlgorithm, Boolean inUse,
                            ZonedDateTime acquiredAt
    ) {
        super(id, cryptoTokenId, keyAlias, keyAlgorithm, inUse, acquiredAt);
    }
}