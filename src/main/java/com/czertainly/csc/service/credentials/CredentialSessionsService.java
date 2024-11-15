package com.czertainly.csc.service.credentials;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.repository.CredentialSessionsRepository;
import com.czertainly.csc.repository.entities.CredentialSessionEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class CredentialSessionsService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialSessionsService.class);
    private final CredentialSessionsRepository credentialSessionsRepository;

    public CredentialSessionsService(CredentialSessionsRepository credentialSessionsRepository) {
        this.credentialSessionsRepository = credentialSessionsRepository;
    }

    public Result<CredentialSessionStatus, TextError> getSessionStatus(UUID sessionId) {
        ZonedDateTime now = ZonedDateTime.now();
        try {
            return credentialSessionsRepository.findById(sessionId)
                                               .map(session -> session.getExpiresIn().isAfter(now) ?
                                                       CredentialSessionStatus.ACTIVE :
                                                       CredentialSessionStatus.EXPIRED
                                               )
                                               .map(Result::<CredentialSessionStatus, TextError>success)
                                               .orElseGet(() -> Result.success(CredentialSessionStatus.NONEXISTENT));
        } catch (Exception e) {
            logger.error("An error occurred while checking the credential session validity.", e);
            return Result.error(TextError.of("An error occurred while checking the credential session validity."));
        }
    }

    public Result<Void, TextError> createSession(CredentialSession session) {
        try {
            CredentialSessionEntity entity = CredentialSessionEntity.fromRecord(session);
            credentialSessionsRepository.save(entity);
            return Result.emptySuccess();
        } catch (Exception e) {
            logger.error("An error occurred while creating the credential session.", e);
            return Result.error(TextError.of("An error occurred while creating the credential session."));
        }
    }

    public Result<UUID, TextError> deleteSession(UUID sessionId) {
        try {
            return getSessionStatus(sessionId)
                    .runIf(status -> status == CredentialSessionStatus.ACTIVE,
                           () -> logger.warn("A valid credential session '{}' is being deleted.", sessionId)
                    )
                    .flatMap(valid -> {
                        try {
                            credentialSessionsRepository.deleteById(sessionId);
                            return Result.success(sessionId);
                        } catch (Exception e) {
                            logger.error("An error occurred while deleting the credential session '{}'.", sessionId, e);
                            return Result.error(
                                    TextError.of(
                                            "An error occurred while deleting the credential session '%s'.",
                                            sessionId
                                    ));
                        }
                    });
        } catch (Exception e) {
            logger.error("An error occurred while deleting the credential session.", e);
            return Result.error(new TextError("An error occurred while deleting the credential session."));
        }
    }

    public Result<CredentialSession, TextError> getSession(UUID sessionId) {
        try {
            return credentialSessionsRepository.findById(sessionId)
                                               .map(session -> new CredentialSession(session.getId(),
                                                                                     session.getCredentialId(),
                                                                                     session.getExpiresIn()
                                               ))
                                               .map(Result::<CredentialSession, TextError>success)
                                               .orElseGet(() -> Result.error(
                                                       TextError.of("Session with ID '%s' not found.", sessionId)));
        } catch (Exception e) {
            logger.error("An error occurred while retrieving the credential session.", e);
            return Result.error(TextError.of("An error occurred while retrieving the credential session."));
        }
    }

    public Result<Integer, TextError> cleanExpiredSessions(Duration expiredSessionsKeepDuration) {
        try {
            ZonedDateTime now = ZonedDateTime.now();
            ZonedDateTime deleteBeforeDateTime = now.minus(expiredSessionsKeepDuration);
            logger.info("Going to delete credential sessions that expired before {}", deleteBeforeDateTime);

            List<UUID> sessionsToDelete = credentialSessionsRepository
                    .findByExpiresInBeforeOrderByExpiresInAsc(deleteBeforeDateTime)
                    .stream()
                    .map(CredentialSessionEntity::getId)
                    .toList();
            logger.info("Found {} credential sessions to delete. [{}]",
                        sessionsToDelete.size(),
                        String.join(", ", sessionsToDelete.stream().map(UUID::toString).toList())
            );

            credentialSessionsRepository.deleteAllById(sessionsToDelete);
            logger.debug("Session deletion completed successfully.");
            return Result.success(sessionsToDelete.size());
        } catch (DateTimeException | ArithmeticException e) {
            logger.error("Failed to calculate the date from which sessions should be deleted.", e);
            return Result.error(TextError.of("Failed to calculate the date from which sessions should be deleted."));
        } catch (IllegalArgumentException | OptimisticLockingFailureException e) {
            logger.error("Failed to execute database operation.", e);
            return Result.error(TextError.of("Failed to execute database operation."));
        } catch (Exception e) {
            logger.error("An unknown error occurred while cleaning expired credential sessions.", e);
            return Result.error(TextError.of("An unknown error occurred while cleaning expired credential sessions."));
        }
    }

    public enum CredentialSessionStatus {
        ACTIVE,
        EXPIRED,
        NONEXISTENT
    }
}
