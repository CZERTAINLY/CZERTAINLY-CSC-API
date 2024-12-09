package com.czertainly.csc.repository;

import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.utils.db.MysqlTest;
import eu.rekawek.toxiproxy.model.ToxicDirection;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;


class SessionKeyRepositoryMysqlTest extends MysqlTest {

    @Autowired
    private SessionKeyRepository sessionKeyRepository;

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
