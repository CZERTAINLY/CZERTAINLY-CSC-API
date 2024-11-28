package com.czertainly.csc.repository.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@Table(name = "one_time_keys")
public class OneTimeKeyEntity extends KeyEntity {

    public OneTimeKeyEntity() {
    }

    public OneTimeKeyEntity(UUID id, int cryptoTokenId, String keyAlias, String keyAlgorithm, Boolean inUse,
                            ZonedDateTime acquiredAt
    ) {
        super(id, cryptoTokenId, keyAlias, keyAlgorithm, inUse, acquiredAt);
    }
}
