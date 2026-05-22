package com.czertainly.csc.repository;

import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.repository.entities.SigningSessionEntity;
import com.czertainly.csc.utils.db.PostgresTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


class SessionKeyRepositoryPostgresTest extends PostgresTest {

    @Autowired
    private SessionKeyRepository sessionKeyRepository;

    @Autowired
    private SessionCredentialsRepository credentialsRepository;

    @Autowired
    private SigningSessionsRepository signingSessionsRepository;

    @Test
    void findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse() {
        // given
        UUID key1 = insertKeyEntity("RSAKey1", 1, "RSA", false, null);
        UUID key2 = insertKeyEntity("RSAKey2", 1, "RSA", true, ZonedDateTime.now());
        UUID key3 = insertKeyEntity("ECDSAKey1", 1, "ECDSA", false, null);
        UUID key4 = insertKeyEntity("ECDSAKey2", 2, "ECDSA", false, null);

        // when
        var key = sessionKeyRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(1, "RSA", false);

        // then
        assertEquals(key1, key.get().getId());

        // when
        key = sessionKeyRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(1, "RSA", true);

        // then
        assertEquals(key2, key.get().getId());

        // when
        key = sessionKeyRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(1, "ECDSA", false);

        // then
        assertEquals(key3, key.get().getId());

        // when
        key = sessionKeyRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(2, "ECDSA", false);

        // then
        assertEquals(key4, key.get().getId());
    }

    @Test
    void countByCryptoTokenIdAndKeyAlgorithmAndInUse() {
        // given
        insertKeyEntity("RSAKey1", 1, "RSA", false, null);
        insertKeyEntity("RSAKey2", 1, "RSA", true, ZonedDateTime.now());
        insertKeyEntity("ECDSAKey1", 1, "ECDSA", false, null);
        insertKeyEntity("ECDSAKey2", 1, "ECDSA", false, null);
        insertKeyEntity("ECDSAKey3", 2, "ECDSA", false, null);

        // when
        var count = sessionKeyRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(1, "RSA", false);

        // then
        assertEquals(1, count);

        // when
        count = sessionKeyRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(1, "RSA", true);

        // then
        assertEquals(1, count);

        // when
        count = sessionKeyRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(1, "ECDSA", false);

        // then
        assertEquals(2, count);

        // when
        count = sessionKeyRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(2, "ECDSA", false);

        // then
        assertEquals(1, count);
    }

    @Test
    void findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc() {
        // given
        insertKeyEntity("Key1", 1, "RSA", false, ZonedDateTime.now().minusHours(1));
        insertKeyEntity("Key2", 1, "RSA", true, ZonedDateTime.now().minusHours(1));
        insertKeyEntity("Key3", 2, "ECDSA", true, ZonedDateTime.now().minusHours(2));
        insertKeyEntity("Key4", 2, "ECDSA", false, ZonedDateTime.now().minusHours(2));
        insertKeyEntity("Key5", 3, "ECDSA", true, ZonedDateTime.now().minusHours(3));

        // when
        var keys = sessionKeyRepository.findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(true, ZonedDateTime.now()
                                                                                                              .minusMinutes(
                                                                                                                      90)
        );

        // then
        assertEquals(2, keys.size());
        assertEquals("Key5", keys.getFirst().getKeyAlias());
        assertEquals("Key3", keys.getLast().getKeyAlias());
    }


    @Test
    void findExpiredKeyCleanupViewsReturnsEmptyListWhenNoKeysInDb() {
        // given
        ZonedDateTime cutoff = ZonedDateTime.now();

        // when
        List<ExpiredKeyCleanupView> result = sessionKeyRepository.findExpiredKeyCleanupViews(cutoff);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void findExpiredKeyCleanupViewsDoesNotReturnKeyNotInUse() {
        // given
        UUID keyId = insertKeyEntity("key", 1, "RSA", false, ZonedDateTime.now().minusHours(1));
        UUID credentialId = insertCredential(keyId);
        insertSession(credentialId);
        ZonedDateTime cutoff = ZonedDateTime.now();

        // when
        List<ExpiredKeyCleanupView> result = sessionKeyRepository.findExpiredKeyCleanupViews(cutoff);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void findExpiredKeyCleanupViewsDoesNotReturnKeyAcquiredAfterCutoff() {
        // given
        ZonedDateTime cutoff = ZonedDateTime.now().minusHours(2);
        UUID keyId = insertKeyEntity("key", 1, "RSA", true, ZonedDateTime.now().minusHours(1));
        UUID credentialId = insertCredential(keyId);
        insertSession(credentialId);

        // when
        List<ExpiredKeyCleanupView> result = sessionKeyRepository.findExpiredKeyCleanupViews(cutoff);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void findExpiredKeyCleanupViewsReturnsKeyAcquiredExactlyAtCutoff() {
        // given
        ZonedDateTime acquiredAt = ZonedDateTime.of(2025, 1, 1, 12, 0, 0, 0, java.time.ZoneOffset.UTC);
        UUID keyId = insertKeyEntity("key", 1, "RSA", true, acquiredAt);
        UUID credentialId = insertCredential(keyId);
        insertSession(credentialId);

        // when — cutoff is exactly equal to acquiredAt, key lifetime has elapsed
        List<ExpiredKeyCleanupView> result = sessionKeyRepository.findExpiredKeyCleanupViews(acquiredAt);

        // then
        assertFalse(result.isEmpty());
    }

    @Test
    void findExpiredKeyCleanupViewsReturnsViewWithAllIdsWhenKeyHasSession() {
        // given
        UUID keyId = insertKeyEntity("key", 1, "RSA", true, ZonedDateTime.now().minusHours(2));
        UUID credentialId = insertCredential(keyId);
        UUID sessionId = insertSession(credentialId);
        ZonedDateTime cutoff = ZonedDateTime.now();

        // when
        List<ExpiredKeyCleanupView> result = sessionKeyRepository.findExpiredKeyCleanupViews(cutoff);

        // then
        assertEquals(1, result.size());
        assertEquals(keyId, result.getFirst().keyId());
        assertEquals(credentialId, result.getFirst().credentialId());
        assertEquals(sessionId, result.getFirst().sessionId());
    }

    @Test
    void findExpiredKeyCleanupViewsReturnsNullSessionIdWhenCredentialHasNoLinkedSession() {
        // given
        UUID keyId = insertKeyEntity("key", 1, "RSA", true, ZonedDateTime.now().minusHours(2));
        UUID credentialId = insertCredential(keyId);
        ZonedDateTime cutoff = ZonedDateTime.now();

        // when — no signing_session row referencing this credential
        List<ExpiredKeyCleanupView> result = sessionKeyRepository.findExpiredKeyCleanupViews(cutoff);

        // then
        assertEquals(1, result.size());
        assertEquals(keyId, result.getFirst().keyId());
        assertEquals(credentialId, result.getFirst().credentialId());
        assertNull(result.getFirst().sessionId());
    }

    private UUID insertCredential(UUID keyId) {
        UUID credentialId = UUID.randomUUID();
        credentialsRepository.save(new SessionCredentialMetadataEntity(
                credentialId, "user", "keyAlias", keyId,
                "endEntity", "signatureQualifier", 1, "cryptoToken"
        ));
        testEntityManager.flush();
        testEntityManager.clear();
        return credentialId;
    }

    private UUID insertSession(UUID credentialId) {
        UUID sessionId = UUID.randomUUID();
        signingSessionsRepository.save(new SigningSessionEntity(
                sessionId, credentialId, ZonedDateTime.now().plusHours(1)
        ));
        testEntityManager.flush();
        testEntityManager.clear();
        return sessionId;
    }

    UUID insertKeyEntity(String keyAlias, int cryptoTokenId, String keyAlgorithm, Boolean inUse,
                         ZonedDateTime acquiredAt
    ) {
        UUID keyId = UUID.randomUUID();

        var entity = new SessionKeyEntity(
                keyId,
                cryptoTokenId,
                keyAlias,
                keyAlgorithm,
                inUse,
                acquiredAt
        );

        sessionKeyRepository.save(entity);
        testEntityManager.flush();
        testEntityManager.clear();

        return keyId;
    }
}
