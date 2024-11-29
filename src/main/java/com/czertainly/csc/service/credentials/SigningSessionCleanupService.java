package com.czertainly.csc.service.credentials;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.service.keys.SessionKeysService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;

@Component
public class SigningSessionCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(SigningSessionCleanupService.class);

    private final SigningSessionsService signingSessionsService;
    private final SessionKeysService sessionKeysService;
    private final SessionCredentialsService sessionCredentialsService;
    private final Duration expiredSessionsKeepTime;
    private final TransactionTemplate transactionTemplate;

    public SigningSessionCleanupService(
            SigningSessionsService signingSessionsService,
            SessionKeysService sessionKeysService, SessionCredentialsService sessionCredentialsService,
            CscConfiguration cscConfiguration, PlatformTransactionManager transactionManager
    ) {
        this.signingSessionsService = signingSessionsService;
        this.sessionKeysService = sessionKeysService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.expiredSessionsKeepTime = cscConfiguration.signingSessions().expiredSessionsKeepTime();
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

    public Result<Void, TextError> deleteSessionAndRelatedResources(SigningSession session) {

        var getSessionCredential = sessionCredentialsService.getSessionCredential(session);
        if (getSessionCredential instanceof Error(var err)) return Result.error(err);
        SessionCredentialMetadata sessionCredentialMetadata = getSessionCredential.unwrap();

        return transactionTemplate.execute(
                (status) ->
                        signingSessionsService
                                .deleteSession(session)
                                .flatMap(v -> sessionCredentialsService.deleteCredential(session.credentialId()))
                                .flatMap(v -> sessionKeysService.deleteKey(sessionCredentialMetadata.keyId()))
                                .mapError(e -> e.extend(
                                                  "An error occurred while deleting session '%s' and it's related resources. %s",
                                                  session.id(), e.getErrorText()
                                          )
                                )
        );

    }
}
