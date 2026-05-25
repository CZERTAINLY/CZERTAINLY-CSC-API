package com.otilm.csc.service.credentials;

import com.otilm.csc.clients.signserver.SignserverClient;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.configuration.csc.CscConfiguration;
import com.otilm.csc.configuration.csc.SigningSessions;
import com.otilm.csc.model.signserver.CryptoToken;
import com.otilm.csc.repository.SessionCredentialsRepository;
import com.otilm.csc.repository.SessionKeyRepository;
import com.otilm.csc.repository.SigningSessionsRepository;
import com.otilm.csc.repository.entities.SessionCredentialMetadataEntity;
import com.otilm.csc.repository.entities.SessionKeyEntity;
import com.otilm.csc.repository.entities.SigningSessionEntity;
import com.otilm.csc.service.keys.SessionKeysService;
import com.otilm.csc.signing.configuration.WorkerRepository;
import com.otilm.csc.utils.db.MysqlTest;
import com.otilm.csc.utils.db.SessionKeyEntityBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Transactional(propagation = Propagation.NEVER)
class SigningSessionCleanupServiceTest extends MysqlTest {

    @Autowired
    private SessionKeyRepository sessionKeyRepository;

    @Autowired
    private SessionCredentialsRepository sessionCredentialsRepository;

    @Autowired
    private SigningSessionsRepository signingSessionsRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private SigningSessionCleanupService cleanupService;
    private SignserverClient signserverClient;
    private WorkerRepository workerRepository;

    @BeforeEach
    void setUp() {
        signserverClient = mock(SignserverClient.class);
        workerRepository = mock(WorkerRepository.class);

        when(workerRepository.getCryptoToken(anyInt())).thenReturn(
                Result.success(new CryptoToken("testToken", 1, List.of()))
        );
        when(signserverClient.removeKeyOkIfNotExists(anyInt(), anyString())).thenReturn(Result.emptySuccess());

        var expiredSessionsKeepTime = Duration.ZERO;
        var assignedKeyLifetime = Duration.ofHours(1);
        cleanupService = buildCleanupService(expiredSessionsKeepTime, assignedKeyLifetime);
    }

    @AfterEach
    void cleanUp() {
        signingSessionsRepository.deleteAll();
        sessionCredentialsRepository.deleteAll();
        sessionKeyRepository.deleteAll();
    }

    // --- cleanSessionsWithExpiredKeyLifetime ---

    @Test
    void skipsCleanupWhenAssignedKeyLifetimeIsNull() {
        // given
        var expiredSessionsKeepTime = Duration.ZERO;
        Duration assignedKeyLifetime = null;
        cleanupService = buildCleanupService(expiredSessionsKeepTime, assignedKeyLifetime);
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId = insertCredential(keyId);
        UUID sessionId = insertSession(credentialId);

        // when
        cleanupService.cleanSessionsWithExpiredKeyLifetime();

        // then
        assertTrue(sessionKeyRepository.existsById(keyId));
        assertTrue(sessionCredentialsRepository.existsById(credentialId));
        assertTrue(signingSessionsRepository.existsById(sessionId));
    }

    @Test
    void doesNotDeleteKeyAcquiredAfterCutoff() {
        // given — key acquired 30 min ago, lifetime is 1h, so cutoff is 1h ago
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusMinutes(30))
                .build());
        UUID credentialId = insertCredential(keyId);
        UUID sessionId = insertSession(credentialId);

        // when
        cleanupService.cleanSessionsWithExpiredKeyLifetime();

        // then
        assertTrue(sessionKeyRepository.existsById(keyId));
        assertTrue(sessionCredentialsRepository.existsById(credentialId));
        assertTrue(signingSessionsRepository.existsById(sessionId));
    }

    @Test
    void deletesSessionCredentialAndKeyWhenKeyHasLinkedSession() {
        // given — key acquired 2h ago, lifetime is 1h
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId = insertCredential(keyId);
        UUID sessionId = insertSession(credentialId);

        // when
        cleanupService.cleanSessionsWithExpiredKeyLifetime();

        // then
        assertFalse(signingSessionsRepository.existsById(sessionId));
        assertFalse(sessionCredentialsRepository.existsById(credentialId));
        assertFalse(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void deletesOrphanedCredentialAndKeyWhenNoSessionExists() {
        // given — key acquired 2h ago with no linked session
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId = insertCredential(keyId);

        // when
        cleanupService.cleanSessionsWithExpiredKeyLifetime();

        // then
        assertFalse(sessionCredentialsRepository.existsById(credentialId));
        assertFalse(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void deletesOrphanedKeyWhenNoCredentialAndSessionExists() {
        // given — key acquired 2h ago with no linked session
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());

        // when
        cleanupService.cleanSessionsWithExpiredKeyLifetime();

        // then
        assertFalse(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void rollsBackCredentialDeletionWhenKeyDeletionFailsForOrphanedCredentialAndKey() {
        // given — orphaned credential+key (no session), key deletion fails in SignServer
        when(signserverClient.removeKeyOkIfNotExists(1, "test-key")).thenReturn(
                Result.error(TextError.of("Signserver failure"))
        );
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId = insertCredential(keyId);

        // when
        assertDoesNotThrow(() -> cleanupService.cleanSessionsWithExpiredKeyLifetime());

        // then — credential deletion is rolled back because key deletion failed
        assertTrue(sessionCredentialsRepository.existsById(credentialId));
        assertTrue(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void doesNotThrowWhenKeyDeletionFailsForOrphanedKeyWithNoCredential() {
        // given — orphaned key with no credential and no session, key deletion fails in SignServer
        when(signserverClient.removeKeyOkIfNotExists(1, "test-key")).thenReturn(
                Result.error(TextError.of("Signserver failure"))
        );
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());

        // when
        assertDoesNotThrow(() -> cleanupService.cleanSessionsWithExpiredKeyLifetime());

        // then — key is not deleted from DB
        assertTrue(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void deletesAllExpiredKeysWhenMultipleExist() {
        // given — two keys both past the 1h lifetime
        UUID keyId1 = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withAlias("key1")
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId1 = insertCredential(keyId1);
        UUID sessionId1 = insertSession(credentialId1);

        UUID keyId2 = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withAlias("key2")
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(3))
                .build());
        UUID credentialId2 = insertCredential(keyId2);
        UUID sessionId2 = insertSession(credentialId2);

        // when
        cleanupService.cleanSessionsWithExpiredKeyLifetime();

        // then
        assertFalse(signingSessionsRepository.existsById(sessionId1));
        assertFalse(sessionCredentialsRepository.existsById(credentialId1));
        assertFalse(sessionKeyRepository.existsById(keyId1));
        assertFalse(signingSessionsRepository.existsById(sessionId2));
        assertFalse(sessionCredentialsRepository.existsById(credentialId2));
        assertFalse(sessionKeyRepository.existsById(keyId2));
    }

    @Test
    void rollsBackAllChangesWhenKeyDeletionFailsDuringCleanSessionsWithExpiredKeyLifetime() {
        // given — key1 deletion will fail on Signserver, key2 will succeed
        when(signserverClient.removeKeyOkIfNotExists(1, "key1")).thenReturn(
                Result.error(TextError.of("Signserver failure"))
        );

        UUID keyId1 = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withAlias("key1")
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId1 = insertCredential(keyId1);
        UUID sessionId1 = insertSession(credentialId1);

        UUID keyId2 = insertKey(SessionKeyEntityBuilder.aSessionKey()
                .withAlias("key2")
                .withInUse(true)
                .withAcquiredAt(ZonedDateTime.now().minusHours(2))
                .build());
        UUID credentialId2 = insertCredential(keyId2);
        UUID sessionId2 = insertSession(credentialId2);

        // when
        assertDoesNotThrow(() -> cleanupService.cleanSessionsWithExpiredKeyLifetime());

        // then — key1 triple rolled back, key2 triple deleted
        assertTrue(signingSessionsRepository.existsById(sessionId1));
        assertTrue(sessionCredentialsRepository.existsById(credentialId1));
        assertTrue(sessionKeyRepository.existsById(keyId1));
        assertFalse(signingSessionsRepository.existsById(sessionId2));
        assertFalse(sessionCredentialsRepository.existsById(credentialId2));
        assertFalse(sessionKeyRepository.existsById(keyId2));
    }

    // --- cleanExpiredSessions ---

    @Test
    void doesNothingWhenNoExpiredSessionsExist() {
        // given
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey().build());
        UUID credentialId = insertCredential(keyId);
        var expiresInFuture = ZonedDateTime.now().plusHours(1);
        UUID sessionId = insertSession(credentialId, expiresInFuture);

        // when
        cleanupService.cleanExpiredSessions();

        // then
        assertTrue(sessionKeyRepository.existsById(keyId));
        assertTrue(sessionCredentialsRepository.existsById(credentialId));
        assertTrue(signingSessionsRepository.existsById(sessionId));
    }

    @Test
    void deletesSessionCredentialAndKeyForExpiredSession() {
        // given — session expired 1h ago, expiredSessionsKeepTime is 0
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey().build());
        UUID credentialId = insertCredential(keyId);
        var expiredAnHourAgo = ZonedDateTime.now().minusHours(1);
        UUID sessionId = insertSession(credentialId, expiredAnHourAgo);

        // when
        cleanupService.cleanExpiredSessions();

        // then
        assertFalse(signingSessionsRepository.existsById(sessionId));
        assertFalse(sessionCredentialsRepository.existsById(credentialId));
        assertFalse(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void doesNotDeleteSessionExpiredLessThanKeepTimeDuration() {
        // given — session expired 1h ago, but keep time is 2h
        var expiredSessionsKeepTime = Duration.ofHours(2);
        Duration assignedKeyLifetime = null; // irrelevant — test exercises cleanExpiredSessions only
        cleanupService = buildCleanupService(expiredSessionsKeepTime, assignedKeyLifetime);
        UUID keyId = insertKey(SessionKeyEntityBuilder.aSessionKey().build());
        UUID credentialId = insertCredential(keyId);
        var expiredAnHourAgo = ZonedDateTime.now().minusHours(1);
        UUID sessionId = insertSession(credentialId, expiredAnHourAgo);

        // when
        cleanupService.cleanExpiredSessions();

        // then
        assertTrue(signingSessionsRepository.existsById(sessionId));
        assertTrue(sessionCredentialsRepository.existsById(credentialId));
        assertTrue(sessionKeyRepository.existsById(keyId));
    }

    @Test
    void deletesOnlyExpiredSessionsLeavingActiveOnesIntact() {
        // given — one expired session, one active session
        var expiredAnHourAgo = ZonedDateTime.now().minusHours(1);
        var expiresInFuture = ZonedDateTime.now().plusHours(1);

        UUID keyId1 = insertKey(SessionKeyEntityBuilder.aSessionKey().withAlias("key1").build());
        UUID credentialId1 = insertCredential(keyId1);
        UUID sessionId1 = insertSession(credentialId1, expiredAnHourAgo);

        UUID keyId2 = insertKey(SessionKeyEntityBuilder.aSessionKey().withAlias("key2").build());
        UUID credentialId2 = insertCredential(keyId2);
        UUID sessionId2 = insertSession(credentialId2, expiresInFuture);

        // when
        cleanupService.cleanExpiredSessions();

        // then
        assertFalse(signingSessionsRepository.existsById(sessionId1));
        assertFalse(sessionCredentialsRepository.existsById(credentialId1));
        assertFalse(sessionKeyRepository.existsById(keyId1));
        assertTrue(signingSessionsRepository.existsById(sessionId2));
        assertTrue(sessionCredentialsRepository.existsById(credentialId2));
        assertTrue(sessionKeyRepository.existsById(keyId2));
    }

    @Test
    void rollsBackAllChangesWhenKeyDeletionFailsDuringCleanExpiredSessions() {
        // given — key1 deletion will fail on Signserver, key2 will succeed
        when(signserverClient.removeKeyOkIfNotExists(1, "key1")).thenReturn(
                Result.error(TextError.of("Signserver failure"))
        );

        var expiredAnHourAgo = ZonedDateTime.now().minusHours(1);

        UUID keyId1 = insertKey(SessionKeyEntityBuilder.aSessionKey().withAlias("key1").build());
        UUID credentialId1 = insertCredential(keyId1);
        UUID sessionId1 = insertSession(credentialId1, expiredAnHourAgo);

        UUID keyId2 = insertKey(SessionKeyEntityBuilder.aSessionKey().withAlias("key2").build());
        UUID credentialId2 = insertCredential(keyId2);
        UUID sessionId2 = insertSession(credentialId2, expiredAnHourAgo);

        // when
        assertDoesNotThrow(() -> cleanupService.cleanExpiredSessions());

        // then — key1 triple rolled back, key2 triple deleted
        assertTrue(signingSessionsRepository.existsById(sessionId1));
        assertTrue(sessionCredentialsRepository.existsById(credentialId1));
        assertTrue(sessionKeyRepository.existsById(keyId1));
        assertFalse(signingSessionsRepository.existsById(sessionId2));
        assertFalse(sessionCredentialsRepository.existsById(credentialId2));
        assertFalse(sessionKeyRepository.existsById(keyId2));
    }

    // --- helpers ---

    private SigningSessionCleanupService buildCleanupService(Duration expiredKeepTime, Duration assignedKeyLifetime) {
        var sessionsService = new SigningSessionsService(signingSessionsRepository);
        var credentialsService = new SessionCredentialsService(
                mock(SignatureQualifierBasedCredentialFactory.class), sessionCredentialsRepository
        );
        var keysService = new SessionKeysService(
                sessionKeyRepository, signserverClient, workerRepository, new TransactionTemplate(transactionManager)
        );

        var cscConfig = mock(CscConfiguration.class);
        when(cscConfig.signingSessions()).thenReturn(
                new SigningSessions(expiredKeepTime, assignedKeyLifetime, "cron", "cron")
        );

        return new SigningSessionCleanupService(
                sessionsService, keysService, credentialsService, sessionKeyRepository, cscConfig, transactionManager
        );
    }

    private UUID insertKey(SessionKeyEntity entity) {
        sessionKeyRepository.save(entity);
        return entity.getId();
    }

    private UUID insertCredential(UUID keyId) {
        UUID id = UUID.randomUUID();
        sessionCredentialsRepository.save(new SessionCredentialMetadataEntity(
                id, "user", "alias", keyId, "endEntity", "qualifier", 1, "testToken"
        ));
        return id;
    }

    private UUID insertSession(UUID credentialId) {
        return insertSession(credentialId, ZonedDateTime.now().plusHours(1));
    }

    private UUID insertSession(UUID credentialId, ZonedDateTime expiresIn) {
        UUID id = UUID.randomUUID();
        signingSessionsRepository.save(new SigningSessionEntity(id, credentialId, expiresIn));
        return id;
    }
}
