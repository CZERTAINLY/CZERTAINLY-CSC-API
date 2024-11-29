package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.service.credentials.SigningSessionCleanupService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SigningSessionsCleanupTrigger {

    private final SigningSessionCleanupService signingSessionsService;

    public SigningSessionsCleanupTrigger(SigningSessionCleanupService signingSessionsService) {
        this.signingSessionsService = signingSessionsService;
    }

    @Scheduled(cron = "${csc.signingSessions.cleanupCronExpression}")
    public void cleanExpiredSessions() {
        signingSessionsService.cleanExpiredSessions();
    }
}
