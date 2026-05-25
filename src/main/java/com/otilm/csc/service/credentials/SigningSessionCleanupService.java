package com.otilm.csc.service.credentials;

import com.otilm.csc.common.result.Error;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.configuration.csc.CscConfiguration;
import com.otilm.csc.model.csc.SessionCredentialMetadata;
import com.otilm.csc.repository.ExpiredKeyCleanupView;
import com.otilm.csc.repository.SessionKeyRepository;
import com.otilm.csc.service.keys.SessionKeysService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.UUID;

@Component
public class SigningSessionCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(SigningSessionCleanupService.class);

    private final SigningSessionsService signingSessionsService;
    private final SessionKeysService sessionKeysService;
    private final SessionCredentialsService sessionCredentialsService;
    private final SessionKeyRepository sessionKeyRepository;
    private final Duration expiredSessionsKeepTime;
    private final Duration assignedKeyLifetime;
    private final TransactionTemplate transactionTemplate;

    public SigningSessionCleanupService(
            SigningSessionsService signingSessionsService,
            SessionKeysService sessionKeysService,
            SessionCredentialsService sessionCredentialsService,
            SessionKeyRepository sessionKeyRepository,
            CscConfiguration cscConfiguration,
            PlatformTransactionManager transactionManager
    ) {
        this.signingSessionsService = signingSessionsService;
        this.sessionKeysService = sessionKeysService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.sessionKeyRepository = sessionKeyRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.expiredSessionsKeepTime = cscConfiguration.signingSessions().expiredSessionsKeepTime();
        this.assignedKeyLifetime = cscConfiguration.signingSessions().assignedKeyLifetime();
    }

    public void cleanExpiredSessions() {
        logger.info(
                "Starting periodic cleanup of expired signing sessions. All sessions that are expired for more than '{}' will be deleted.",
                expiredSessionsKeepTime
        );
        signingSessionsService.getExpiredSessions(expiredSessionsKeepTime)
                              .consume(expiredSessions -> {
                                  for (SigningSession expired : expiredSessions) {
                                      deleteSessionAndRelatedResources(expired).consumeError(
                                              e -> logger.error(e.getErrorText()));
                                  }
                              })
                              .consumeError(
                                      err -> logger.error("An error occurred while cleaning up expired sessions. {}",
                                                          err.getErrorText()
                                      )
                              );
    }

    public void cleanSessionsWithExpiredKeyLifetime() {
        if (assignedKeyLifetime == null) {
            logger.warn("assignedKeyLifetime is not configured, skipping key lifetime cleanup.");
            return;
        }
        ZonedDateTime cutoff = ZonedDateTime.now(ZoneOffset.UTC).minus(assignedKeyLifetime);
        logger.info("Deleting session keys assigned before '{}' (assigned_key_lifetime={}).", cutoff, assignedKeyLifetime);

        try {
            sessionKeyRepository.findExpiredKeyCleanupViews(cutoff)
                    .forEach(this::deleteExpiredKeyResources);
        } catch (Exception e) {
            logger.error("Failed to retrieve session keys for lifetime cleanup.", e);
        }
    }

    private Result<Void, TextError> deleteSessionAndRelatedResources(SigningSession session) {

        var getSessionCredential = sessionCredentialsService.getSessionCredential(session);
        if (getSessionCredential instanceof Error(var err)) return Result.error(err);
        SessionCredentialMetadata sessionCredentialMetadata = getSessionCredential.unwrap();

        return transactionTemplate.execute(
                (status) ->
                        signingSessionsService
                                .deleteSession(session)
                                .flatMap(v -> sessionCredentialsService.deleteCredential(session.credentialId()))
                                .flatMap(v -> sessionKeysService.deleteKey(sessionCredentialMetadata.keyId()))
                                .mapError(e -> {
                                    status.setRollbackOnly();
                                    return e.extend(
                                            "An error occurred while deleting session '%s' and its related resources. %s",
                                            session.id(), e.getErrorText()
                                    );
                                })
        );

    }

    private void deleteExpiredKeyResources(ExpiredKeyCleanupView view) {
        if (view.sessionId() != null) {
            Result<?, ?> result = transactionTemplate.execute(status ->
                    signingSessionsService.deleteSessionById(view.sessionId())
                            .flatMap(v -> sessionCredentialsService.deleteCredential(view.credentialId()))
                            .flatMap(v -> sessionKeysService.deleteKey(view.keyId()))
                            .mapError(e -> {
                                status.setRollbackOnly();
                                return e.extend(
                                        "Failed to delete session '%s' and related resources. %s",
                                        view.sessionId(), e.getErrorText()
                                );
                            })
            );
            if (result instanceof Error(TextError e)) {
                logger.error(e.getErrorText());
            }
        } else {
            deleteOrphanedCredentialAndKey(view.credentialId(), view.keyId());
        }
    }

    private void deleteOrphanedCredentialAndKey(UUID credentialId, UUID keyId) {
        logger.warn("No session found for key '{}', deleting orphaned resources directly.", keyId);
        Result<?, ?> result = transactionTemplate.execute(status -> {
            Result<Void, TextError> r = credentialId != null
                    ? sessionCredentialsService.deleteCredential(credentialId)
                    : Result.emptySuccess();
            return r
                    .flatMap(v -> sessionKeysService.deleteKey(keyId))
                    .mapError(e -> {
                        status.setRollbackOnly();
                        return e.extend(
                                "Failed to delete orphaned credential '%s' and key '%s'. %s",
                                credentialId, keyId, e.getErrorText()
                        );
                    });
        });
        if (result instanceof Error(TextError e)) {
            logger.error(e.getErrorText());
        }
    }
}
