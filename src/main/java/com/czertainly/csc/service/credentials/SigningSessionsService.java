package com.czertainly.csc.service.credentials;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.repository.SigningSessionsRepository;
import com.czertainly.csc.repository.entities.SigningSessionEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SigningSessionsService {

    private static final Logger logger = LoggerFactory.getLogger(SigningSessionsService.class);
    private final SigningSessionsRepository signingSessionsRepository;

    public SigningSessionsService(SigningSessionsRepository signingSessionsRepository) {
        this.signingSessionsRepository = signingSessionsRepository;
    }

    public Result<Optional<SigningSession>, TextError> getSession(UUID sessionId) {
        try {
            Optional<SigningSession> session = signingSessionsRepository.findById(sessionId)
                                                                        .map(entity -> new SigningSession(
                                                                                entity.getId(),
                                                                                entity.getCredentialId(),
                                                                                entity.getExpiresIn(),
                                                                                resolveSessionStatus(entity)
                                                                        ));
            logger.trace("Retrieved signing session '{}'.", session);
            return Result.success(session);
        } catch (Exception e) {
            logger.error("An error occurred while retrieving the signing session.", e);
            return Result.error(TextError.of("An error occurred while retrieving the signing session."));
        }
    }

    public Result<SigningSession, TextError> saveNewSession(SigningSession newSession) {
        try {
            logger.trace("Saving new signing session '{}'.", newSession);
            if (newSession.status() != CredentialSessionStatus.NEW) {
                return Result.error(TextError.of("Only sessions with status 'NEW' can be saved."));
            }
            SigningSessionEntity entity = SigningSessionEntity.fromRecord(newSession);
            SigningSessionEntity savedEntity = signingSessionsRepository.save(entity);

            SigningSession s = new SigningSession(
                    savedEntity.getId(),
                    savedEntity.getCredentialId(),
                    savedEntity.getExpiresIn(),
                    resolveSessionStatus(savedEntity)
            );
            return Result.success(s);
        } catch (Exception e) {
            logger.error("An error occurred while saving new signing session.", e);
            return Result.error(TextError.of("An error occurred while saving new signing session."));
        }
    }

    public Result<Void, TextError> deleteSession(SigningSession session) {
            logger.trace("Deleting signing session '{}'.", session);
            if (session.status() == CredentialSessionStatus.ACTIVE) {
                logger.warn("An active signing session '{}' is being deleted.", session);
            }

            try {
                signingSessionsRepository.deleteById(session.id());
                logger.debug("Deleted signing session '{}'.", session);
                return Result.emptySuccess();
            } catch (Exception e) {
                logger.error("An error occurred while deleting the signing session '{}'.", session, e);
                return Result.error(
                        TextError.of(
                                "An error occurred while deleting the signing session '%s'.",
                                session.id()
                        ));
            }
    }

    public Result<List<SigningSession>, TextError> getExpiredSessions(Duration expiredSessionsKeepDuration) {
        try {
            ZonedDateTime now = ZonedDateTime.now();
            ZonedDateTime olderThen = now.minus(expiredSessionsKeepDuration);
            logger.debug("Looking for sessions that expired before '{}'", olderThen);

            List<SigningSession> sessionsToDelete = signingSessionsRepository
                    .findByExpiresInBeforeOrderByExpiresInAsc(olderThen)
                    .stream()
                    .map(entity -> new SigningSession(
                            entity.getId(),
                            entity.getCredentialId(),
                            entity.getExpiresIn(),
                            resolveSessionStatus(entity)
                    ))
                    .toList();
            logger.debug("Found {} signing sessions to delete. [{}]",
                         sessionsToDelete.size(),
                         String.join(", ", sessionsToDelete.stream().map(s -> s.id().toString()).toList())
            );
            return Result.success(sessionsToDelete);
        } catch (DateTimeException | ArithmeticException e) {
            logger.error("Failed to calculate the date from which sessions should be deleted.", e);
            return Result.error(TextError.of("Failed to calculate the date from which sessions should be deleted."));
        } catch (IllegalArgumentException | OptimisticLockingFailureException e) {
            logger.error("Failed to execute database operation.", e);
            return Result.error(TextError.of("Failed to execute database operation."));
        } catch (Exception e) {
            logger.error("An unknown error occurred while searching for expired signing sessions.", e);
            return Result.error(
                    TextError.of("An unknown error occurred while searching for expired signing sessions."));
        }
    }

    private static CredentialSessionStatus resolveSessionStatus(SigningSessionEntity session) {
        ZonedDateTime now = ZonedDateTime.now();
        CredentialSessionStatus status = session.getExpiresIn().isAfter(now) ?
                CredentialSessionStatus.ACTIVE :
                CredentialSessionStatus.EXPIRED;
        logger.trace("The status of the session '{}' was resolved to '{}'. The session expires at '{}'. Now is '{}'.",
                     session.getId(), status, session.getExpiresIn().toLocalDateTime(), now.toLocalDateTime()
        );
        return status;
    }
}
