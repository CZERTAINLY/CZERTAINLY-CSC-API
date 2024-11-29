package com.czertainly.csc.service.credentials;

import com.czertainly.csc.repository.SigningSessionsRepository;
import com.czertainly.csc.repository.SessionCredentialsRepository;
import com.czertainly.csc.repository.SessionKeyRepository;
import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.repository.entities.SigningSessionEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(SigningSessionsService.class)
@Testcontainers
class SigningSessionsServiceTest {

    @Container
    static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.4");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", mysql::getJdbcUrl);
        registry.add("spring.datasource.username", mysql::getUsername);
        registry.add("spring.datasource.password", mysql::getPassword);
        registry.add("spring.flyway.schemas", () -> "test");
        registry.add("spring.flyway.locations", () -> "classpath:db/migration,classpath:db/specific/{vendor}");
    }

    @Autowired
    TestEntityManager testEntityManager;

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
    public void cleanExpiredSessionsWillDeleteExpiredSessionThatAreExpiredAtLeastGivenAmountOfTime() {
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
    public void cleanExpiredSessionsWillNotDeleteExpiredSessionThatAreExpiredLessThanGivenAmountOfTime() {
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