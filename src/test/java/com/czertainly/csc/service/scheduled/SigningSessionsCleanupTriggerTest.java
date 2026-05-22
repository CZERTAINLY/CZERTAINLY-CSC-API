package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.configuration.csc.SigningSessions;
import com.czertainly.csc.service.credentials.SigningSessionCleanupService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.mockito.Mockito.*;

class SigningSessionsCleanupTriggerTest {

    private SigningSessionCleanupService cleanupService;

    @BeforeEach
    void setUp() {
        cleanupService = mock(SigningSessionCleanupService.class);
    }

    @Test
    void callsCleanSessionsWithExpiredKeyLifetimeWhenAssignedKeyLifetimeIsConfigured() {
        // given
        var assignedKeyLifetime = Duration.ofHours(1);
        var trigger = buildTrigger(assignedKeyLifetime);

        // when
        trigger.cleanExpiredSessions();

        // then
        verify(cleanupService).cleanSessionsWithExpiredKeyLifetime();
        verify(cleanupService).cleanExpiredSessions();
    }

    @Test
    void callsCleanExpiredSessionsWhenAssignedKeyLifetimeIsNull() {
        // given
        Duration assignedKeyLifetime = null;
        var trigger = buildTrigger(assignedKeyLifetime);

        // when
        trigger.cleanExpiredSessions();

        // then
        verify(cleanupService).cleanExpiredSessions();
        verify(cleanupService, never()).cleanSessionsWithExpiredKeyLifetime();
    }

    private SigningSessionsCleanupTrigger buildTrigger(Duration assignedKeyLifetime) {
        var cscConfig = mock(CscConfiguration.class);
        when(cscConfig.signingSessions()).thenReturn(
                new SigningSessions(Duration.ZERO, assignedKeyLifetime, "cron", "cron")
        );
        return new SigningSessionsCleanupTrigger(cleanupService, cscConfig);
    }
}
