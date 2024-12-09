package com.czertainly.csc.repository;

import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.repository.entities.SigningSessionEntity;
import com.czertainly.csc.utils.db.MysqlTest;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ExceptionAssertions.assertThrowsAndMessageContains;
import static org.junit.jupiter.api.Assertions.assertEquals;


class SigningSessionsRepositoryMysqlTest extends MysqlTest {

    @Autowired
    SigningSessionsRepository signingSessionsRepository;

    @Autowired
    SessionCredentialsRepository credentialsRepository;

    @Autowired
    SessionKeyRepository keyRepository;

    @Test
    public void expiresInPointsToTheSameInstantWhenRetrievedBack() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime expiresIn = ZonedDateTime.of(2020, 10, 5, 12, 0, 0, 0, ZoneOffset.ofHours(-5));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, expiresIn);

        // when
        var e = signingSessionsRepository.findById(sessionId);

        // then
        ZonedDateTime expectedExpiresIn = ZonedDateTime.of(2020, 10, 5, 17, 0, 0, 0, ZoneOffset.UTC);
        assertEquals(expectedExpiresIn, e.orElseThrow().getExpiresIn());
    }

    @Test
    public void canFindByExpiresIn() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();
        ZonedDateTime expiresIn1 = ZonedDateTime.of(2020, 10, 5, 12, 0, 0, 0, ZoneOffset.UTC);
        ZonedDateTime expiresIn2 = ZonedDateTime.of(2020, 10, 5, 13, 0, 0, 0, ZoneOffset.UTC);
        ZonedDateTime expiresIn3 = ZonedDateTime.of(2020, 10, 5, 14, 0, 0, 0, ZoneOffset.UTC);
        UUID session1Id = createAndInsertSessionIntoDB(credentialId, expiresIn1);
        UUID session2Id = createAndInsertSessionIntoDB(credentialId, expiresIn2);
        UUID session3Id = createAndInsertSessionIntoDB(credentialId, expiresIn3);

        // given
        ZonedDateTime testTime = ZonedDateTime.of(2020, 10, 5, 13, 30, 0, 0, ZoneOffset.UTC);

        // when
        var credentials = signingSessionsRepository.findByExpiresInBeforeOrderByExpiresInAsc(testTime);

        // then
        assertEquals(2, credentials.size());
        assertEquals(session1Id, credentials.get(0).getId());
        assertEquals(session2Id, credentials.get(1).getId());
    }

    @Test
    public void sessionMustReferenceExistingCredential() {
        // setup
        UUID realCredentialID = createCredentialAndInsertIntoDB();

        // given
        UUID nonExistentCredentialId = UUID.randomUUID();
        assert !nonExistentCredentialId.equals(realCredentialID);

        // when
        Executable ex = () -> createAndInsertSessionIntoDB(nonExistentCredentialId);

        // then
        assertThrowsAndMessageContains(ConstraintViolationException.class, "foreign key constraint", ex);

    }

    private UUID createCredentialAndInsertIntoDB() {
        UUID keyId = UUID.randomUUID();
        String keyAlias = "testKey";
        UUID credentialId = UUID.randomUUID();

        keyRepository.save(new SessionKeyEntity(
                keyId, 1, keyAlias, "RSA", false, null
        ));

        credentialsRepository.save(new SessionCredentialMetadataEntity(
                credentialId,
                "user",
                keyAlias,
                keyId,
                "endEntityName",
                "signatureQualifier",
                1,
                "cryptoTokenName"
        ));
        testEntityManager.flush();
        testEntityManager.clear();
        return credentialId;
    }

    private UUID createAndInsertSessionIntoDB(UUID credentialId, ZonedDateTime expiresIn) {
        UUID sessionId = UUID.randomUUID();

        signingSessionsRepository.save(
                new SigningSessionEntity(
                        sessionId,
                        credentialId,
                        expiresIn
                )
        );
        testEntityManager.flush();
        testEntityManager.clear();
        return sessionId;
    }

    private UUID createAndInsertSessionIntoDB(UUID credentialId) {
        ZonedDateTime expiresIn = ZonedDateTime.now().plusDays(1);
        return createAndInsertSessionIntoDB(credentialId, expiresIn);
    }
}