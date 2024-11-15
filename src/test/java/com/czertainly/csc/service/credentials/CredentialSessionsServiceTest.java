package com.czertainly.csc.service.credentials;

import com.czertainly.csc.repository.CredentialSessionsRepository;
import com.czertainly.csc.repository.CredentialsRepository;
import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import com.czertainly.csc.repository.entities.CredentialSessionEntity;
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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(CredentialSessionsService.class)
@Testcontainers
class CredentialSessionsServiceTest {

    @Container
    static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.4");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", mysql::getJdbcUrl);
        registry.add("spring.datasource.username", mysql::getUsername);
        registry.add("spring.datasource.password", mysql::getPassword);
        registry.add("spring.flyway.schemas", () -> "test");
    }

    @Autowired
    TestEntityManager testEntityManager;

    @Autowired
    CredentialSessionsService credentialSessionsService;

    @Autowired
    CredentialSessionsRepository credentialSessionsRepository;

    @Autowired
    CredentialsRepository credentialsRepository;

    @Test
    public void isValidSessionReturnsTrueIfTheSessionExistsAndIsNotExpired() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().plus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);

        // when
        var result = credentialSessionsService.isActiveSession(sessionId);

        // then
        assertTrue(result.unwrap());
    }

    @Test
    public void isValidSessionReturnsFalseIfTheSessionExistsAndIsExpired() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);

        // when
        var result = credentialSessionsService.isActiveSession(sessionId);

        // then
        assertFalse(result.unwrap());
    }

    @Test
    public void isActiveSessionReturnsFalseIfTheSessionDoesNotExist() {
        // given
        UUID nonExistentSessionId = UUID.randomUUID();

        // when
        var result = credentialSessionsService.isActiveSession(nonExistentSessionId);

        // then
        assertFalse(result.unwrap());
    }

    @Test
    public void cleanExpiredSessionsWillDeleteExpiredSession() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);
        assertTrue(credentialSessionsRepository.existsById(sessionId));

        // when
        credentialSessionsService.cleanExpiredSessions(Duration.ZERO);

        // then
        assertFalse(credentialSessionsRepository.existsById(sessionId));
    }

    @Test
    public void cleanExpiredSessionsWillDeleteExpiredSessionThatAreExpiredAtLeastGivenAmountOfTime() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(3));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);
        assertTrue(credentialSessionsRepository.existsById(sessionId));

        // when
        credentialSessionsService.cleanExpiredSessions(Duration.ofHours(2));

        // then
        assertFalse(credentialSessionsRepository.existsById(sessionId));
    }

    @Test
    public void cleanExpiredSessionsWillNotDeleteExpiredSessionThatAreExpiredLessThanGivenAmountOfTime() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime sessionExpiresIn = ZonedDateTime.now().minus(Duration.ofHours(1));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, sessionExpiresIn);
        assertTrue(credentialSessionsRepository.existsById(sessionId));

        // when
        credentialSessionsService.cleanExpiredSessions(Duration.ofHours(2));

        // then
        assertTrue(credentialSessionsRepository.existsById(sessionId));
    }

    private UUID createAndInsertSessionIntoDB(UUID credentialId, ZonedDateTime expiresIn) {
        UUID sessionId = UUID.randomUUID();

        credentialSessionsRepository.save(
                new CredentialSessionEntity(
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
        UUID credentialId = UUID.randomUUID();
        credentialsRepository.save(new CredentialMetadataEntity(
                credentialId,
                "user",
                "keyAlias",
                "credentialProfile",
                "endEntityName",
                "currentCertificateSn",
                "currentCertificateIssuer",
                "signatureQualifier",
                1,
                "scal",
                "cryptoTokenName",
                "description",
                false
        ));
        testEntityManager.flush();
        testEntityManager.clear();
        return credentialId;
    }

}