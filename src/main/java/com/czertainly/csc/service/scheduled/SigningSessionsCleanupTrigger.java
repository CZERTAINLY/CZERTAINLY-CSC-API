package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.service.credentials.SigningSessionCleanupService;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@Profile("session-keys-cleaner")
public class SigningSessionsCleanupTrigger {

    private final SigningSessionCleanupService signingSessionsService;
    private final boolean keyLifetimeCleanupEnabled;

    public SigningSessionsCleanupTrigger(SigningSessionCleanupService signingSessionsService,
                                         CscConfiguration cscConfiguration) {
        this.signingSessionsService = signingSessionsService;
        this.keyLifetimeCleanupEnabled = cscConfiguration.signingSessions().assignedKeyLifetime() != null;
    }

    @Scheduled(cron = "${csc.signingSessions.cleanupCronExpression:0 0 * * * *}")
    public void cleanExpiredSessions() {
        if (keyLifetimeCleanupEnabled) {
            signingSessionsService.cleanSessionsWithExpiredKeyLifetime();
        } else {
            signingSessionsService.cleanExpiredSessions();
        }
    }
}
