package com.czertainly.csc.repository;


import com.czertainly.csc.repository.entities.SigningSessionEntity;
import org.hibernate.exception.JDBCConnectionException;
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
import java.util.UUID;

@Repository
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
public interface SigningSessionsRepository extends CrudRepository<SigningSessionEntity, UUID> {

    List<SigningSessionEntity> findByExpiresInBeforeOrderByExpiresInAsc(ZonedDateTime instant);

}
