package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.service.credentials.CredentialSessionsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class CredentialSessionsCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialSessionsCleanupService.class);
    private final CredentialSessionsService credentialSessionsService;
    private final Duration expiredSessionsKeepTime;

    public CredentialSessionsCleanupService(
            CredentialSessionsService credentialSessionsService,
            @Value("${csc.credentialSessions.expiredSessionsKeepTime}") String expiredSessionsKeepTime
    ) {
        this.credentialSessionsService = credentialSessionsService;
        try {
            this.expiredSessionsKeepTime = Duration.parse(expiredSessionsKeepTime);
        } catch (Exception e) {
            throw new ApplicationConfigurationException(
                    "Invalid duration format for csc.credentialSessions.expiredSessionsKeepTime", e);
        }
    }

    @Scheduled(cron = "${csc.credentialSessions.cleanupCronExpression}")
    public void cleanExpiredSessions() {
        logger.info(
                "Starting periodic cleanup of expired credential sessions. All sessions that are expired for more than {} will be deleted.",
                expiredSessionsKeepTime
        );
        credentialSessionsService.cleanExpiredSessions(expiredSessionsKeepTime)
                .consumeError(e -> logger.error("An error occurred while cleaning expired credential sessions. {}", e.getErrorText()))
                .consume(numDeleted -> logger.info("Periodic cleanup of expired credential sessions has finished. {} sessions were deleted.", numDeleted));
    }
}
