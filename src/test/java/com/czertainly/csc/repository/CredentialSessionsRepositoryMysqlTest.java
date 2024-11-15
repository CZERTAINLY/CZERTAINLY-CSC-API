package com.czertainly.csc.repository;

import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import com.czertainly.csc.repository.entities.CredentialSessionEntity;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ExceptionAssertions.assertThrowsAndMessageContains;
import static org.junit.jupiter.api.Assertions.assertEquals;


@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class CredentialSessionsRepositoryMysqlTest {

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
    private TestEntityManager testEntityManager;

    @Autowired
    CredentialSessionsRepository credentialSessionsRepository;

    @Autowired
    CredentialsRepository credentialsRepository;

    @Test
    public void expiresInPointsToTheSameInstantWhenRetrievedBack() {
        // setup
        UUID credentialId = createCredentialAndInsertIntoDB();

        // given
        ZonedDateTime expiresIn = ZonedDateTime.of(2020, 10, 5, 12, 0, 0, 0, ZoneOffset.ofHours(-5));
        UUID sessionId = createAndInsertSessionIntoDB(credentialId, expiresIn);

        // when
        var e = credentialSessionsRepository.findById(sessionId);

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
        var credentials = credentialSessionsRepository.findByExpiresInBeforeOrderByExpiresInAsc(testTime);

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

    private UUID createAndInsertSessionIntoDB(UUID credentialId) {
        ZonedDateTime expiresIn = ZonedDateTime.now().plusDays(1);
        return createAndInsertSessionIntoDB(credentialId, expiresIn);
    }
}