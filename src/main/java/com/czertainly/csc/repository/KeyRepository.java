package com.czertainly.csc.repository;

import com.czertainly.csc.repository.entities.KeyEntity;
import jakarta.persistence.LockModeType;
import org.hibernate.exception.JDBCConnectionException;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.repository.CrudRepository;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.CannotCreateTransactionException;

import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientException;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Retryable(
        retryFor = {
                SQLRecoverableException.class,
                SQLTransientException.class,
                SQLNonTransientConnectionException.class,
                JDBCConnectionException.class,
                CannotCreateTransactionException.class
        },
        noRetryFor = {Exception.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 1000, multiplier = 2),
        listeners = {"retryLoggingListener"})
public interface KeyRepository<T extends KeyEntity> extends CrudRepository<T, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<T> findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(int cryptoTokenId, String keyAlgorithm, boolean inUse);

    int countByCryptoTokenIdAndKeyAlgorithmAndInUse(int cryptoTokenId, String keyAlgorithm, boolean inUse);

    List<T> findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(boolean inUse, ZonedDateTime instant);
}
