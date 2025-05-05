package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.service.keys.OneTimeKeyCleanupService;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@Profile("one-time-keys-cleaner")
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