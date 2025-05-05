package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.service.keys.OneTimeKeyCleanupService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class OneTimeKeysCleanupTrigger {

    private final OneTimeKeyCleanupService oneTimeKeyCleanupService;

    public OneTimeKeysCleanupTrigger(OneTimeKeyCleanupService oneTimeKeyCleanupService) {
        this.oneTimeKeyCleanupService = oneTimeKeyCleanupService;
    }

    @Scheduled(cron = "${csc.oneTimeKeys.cleanupCronExpression}")
    public void cleanExpiredSessions() {
        oneTimeKeyCleanupService.cleanUsedUpKeys();
    }
}