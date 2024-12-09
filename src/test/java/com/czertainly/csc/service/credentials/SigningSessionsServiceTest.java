package com.czertainly.csc.service.credentials;

import com.czertainly.csc.repository.SessionCredentialsRepository;
import com.czertainly.csc.repository.SessionKeyRepository;
import com.czertainly.csc.repository.SigningSessionsRepository;
import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.repository.entities.SigningSessionEntity;
import com.czertainly.csc.utils.db.MysqlTest;
import com.czertainly.csc.utils.signing.aSigningSession;
import eu.rekawek.toxiproxy.model.ToxicDirection;
import jakarta.persistence.EntityTransaction;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.transaction.TestTransaction;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ResultAssertions.*;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(SigningSessionsService.class)
@Testcontainers
class SigningSessionsServiceTest extends MysqlTest {

    @Autowired
    SigningSessionsService signingSessionsService;

    @Autowired
    SigningSessionsRepository signingSessionsRepository;

    @Autowired
    SessionCredentialsRepository credentialsRepository;

    @Autowired
    SessionKeyRepository sessionKeyRepository;


    @Test
    public void getSessionReturnsActiveSessionIfTheSessionExistsAndIsNotExpired() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().plus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);

        // when
        var result = signingSessionsService.getSession(sessionId);

        // then
        Optional<SigningSession> session = result.unwrap();
        assertTrue(session.isPresent());
        assertEquals(CredentialSessionStatus.ACTIVE, session.get().status());
    }

    @Test
    public void getSessionReturnsExpiredSessionIfTheSessionExistsAndIsExpired() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);

        // when
        var result = signingSessionsService.getSession(sessionId);

        // then
        Optional<SigningSession> session = result.unwrap();
        assertTrue(session.isPresent());
        assertEquals(CredentialSessionStatus.EXPIRED, session.get().status());
    }

    @Test
    public void getSessionReturnsNullIfTheSessionDoesNotExist() {
        // given
        UUID nonExistentSessionId = UUID.randomUUID();

        // when
        var result = signingSessionsService.getSession(nonExistentSessionId);

        // then
        Optional<SigningSession> session = result.unwrap();
        assertFalse(session.isPresent());
    }

    @Test
    @Transactional(propagation=Propagation.NEVER)
    public void getSessionReturnsErrorGetSessionFails() throws IOException {
        // setup
        UUID nonExistentSessionId = UUID.randomUUID();
        proxy.toxics().timeout("timeout-toxics", ToxicDirection.UPSTREAM, 2);

        // when
        var result = signingSessionsService.getSession(nonExistentSessionId);

        // then
        assertErrorContains(result, "An error occurred while retrieving the signing session");
    }

    @Test
    public void saveNewSessionWillSaveNewSessionAndReturnActiveSession() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        SigningSession newSession = aSigningSession.instance()
                .withCredentialId(credentialId)
                .withStatus(CredentialSessionStatus.NEW)
                .build();

        // when
        var result = signingSessionsService.saveNewSession(newSession);

        // then
        SigningSession savedSession = assertSuccessAndGet(result);
        assertEquals(newSession.id(), savedSession.id());
        assertEquals(newSession.credentialId(), savedSession.credentialId());
        assertEquals(CredentialSessionStatus.ACTIVE, savedSession.status());
    }

    @Test
    public void saveNewSessionWillNotSaveSessionThatIsNotNew() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();
        SigningSession newSession = aSigningSession.instance()
                                                   .withCredentialId(credentialId)
                                                   .withStatus(CredentialSessionStatus.ACTIVE)
                                                   .build();

        // when
        var result = signingSessionsService.saveNewSession(newSession);

        // then
        assertErrorContains(result, "Only sessions with status 'NEW' can be saved");
    }

    @Test
    @Transactional(propagation=Propagation.NEVER)
    public void saveNewSessionWillReturnErrorIfSaveFails() throws IOException {
        // setup
        SigningSession newSession = aSigningSession.instance().build();

        // given
       proxy.toxics().timeout("timeout-toxics", ToxicDirection.UPSTREAM, 2);

        // when
        var result = signingSessionsService.saveNewSession(newSession);

        // then
        assertErrorContains(result, "An error occurred while saving new signing session");
    }

    @Test
    public void deleteWillDeleteSession() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, ZonedDateTime.now().plus(Duration.ofHours(1)));
        SigningSession session = aSigningSession.instance()
                                                   .withId(sessionId)
                                                   .withCredentialId(credentialId)
                                                   .withExpiresIn(ZonedDateTime.now().plus(Duration.ofHours(1)))
                                                   .withStatus(CredentialSessionStatus.ACTIVE)
                                                   .build();

        // when
        var result = signingSessionsService.deleteSession(session);

        // then
        assertSuccessAndGet(result);
        assertFalse(signingSessionsRepository.existsById(sessionId));
    }

    @Test
    public void deleteSessionThatDoesNotExistInDBWillReturnSuccess() {
        // setup
        SigningSession session = aSigningSession.instance().build();

        // when
        var result = signingSessionsService.deleteSession(session);

        // then
        assertSuccess(result);
    }


    @Test
    @Transactional(propagation = Propagation.NEVER)
    public void deleteSessionReturnsErrorIfDeleteFails() throws IOException {
        // setup
        SigningSession session = aSigningSession.instance().build();

        // given
        proxy.toxics().timeout("timeout-toxics", ToxicDirection.UPSTREAM, 1);

        // when
        var result = signingSessionsService.deleteSession(session);

        // then
        assertErrorContains(result, session.id().toString());
    }

    @Test
    public void getExpiredSessionsWillReturnExpiredSessions() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);
        assertTrue(signingSessionsRepository.existsById(sessionId));

        // when
        var getExpiredSessionsResult = signingSessionsService.getExpiredSessions(Duration.ZERO);

        // then
        var expiredSessions = assertSuccessAndGet(getExpiredSessionsResult);
        assertEquals(1, expiredSessions.size());
        assertTrue(expiredSessions.stream().anyMatch(s -> s.id().equals(sessionId)));
    }

    @Test
    @Transactional(propagation = Propagation.NEVER)
    public void getExpiredSessionsWillReturnErrorWhenGettingExpiredSessionFails() throws IOException {
        // given
        proxy.toxics().timeout("timeout-toxics", ToxicDirection.UPSTREAM, 1);

        // when
        var getExpiredSessionsResult = signingSessionsService.getExpiredSessions(Duration.ZERO);

        // then
        assertError(getExpiredSessionsResult);
    }

    @Test
    public void getExpiredSessionsWillReturnExpiredSessionThatAreExpiredAtLeastGivenAmountOfTime() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(3));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);
        assertTrue(signingSessionsRepository.existsById(sessionId));

        // when
        var getExpiredSessionsResult = signingSessionsService.getExpiredSessions(Duration.ofHours(2));

        // then
        var expiredSessions = assertSuccessAndGet(getExpiredSessionsResult);
        assertEquals(1, expiredSessions.size());
        assertTrue(expiredSessions.stream().anyMatch(s -> s.id().equals(sessionId)));
    }

    @Test
    public void getExpiredSessionsWillNotReturnExpiredSessionThatAreExpiredLessThanGivenAmountOfTime() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);
        assertTrue(signingSessionsRepository.existsById(sessionId));

        // when
        var getExpiredSessionsResult = signingSessionsService.getExpiredSessions(Duration.ofHours(2));

        // then
        var expiredSessions = assertSuccessAndGet(getExpiredSessionsResult);
        assertIterableEquals(List.of(), expiredSessions);
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

    private UUID createCredentialAndInsertIntoDB() {

        SessionKeyEntity keyEntity = new SessionKeyEntity(
                UUID.randomUUID(),
                1,
                "myKeyAlias",
                "RSA",
                false,
                ZonedDateTime.now()
        );
        sessionKeyRepository.save(keyEntity);

        UUID credentialId = UUID.randomUUID();
        credentialsRepository.save(new SessionCredentialMetadataEntity(
                credentialId,
                "user",
                "keyAlias",
                keyEntity.getId(),
                "signatureQualifier",
                "endEntityName",
                1,
                "cryptoTokenName"
        ));
        testEntityManager.flush();
        testEntityManager.clear();
        return credentialId;
    }

}