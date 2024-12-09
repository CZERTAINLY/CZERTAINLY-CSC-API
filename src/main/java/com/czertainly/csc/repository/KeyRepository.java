package com.czertainly.csc.repository;

import com.czertainly.csc.repository.entities.KeyEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

public interface KeyRepository<T extends KeyEntity> extends CrudRepository<T, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<T> findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(int cryptoTokenId, String keyAlgorithm, boolean inUse);

    int countByCryptoTokenIdAndKeyAlgorithmAndInUse(int cryptoTokenId, String keyAlgorithm, boolean inUse);
}
