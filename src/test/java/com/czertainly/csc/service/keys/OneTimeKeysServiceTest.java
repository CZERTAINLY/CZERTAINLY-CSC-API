package com.czertainly.csc.service.keys;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.repository.KeyRepository;
import com.czertainly.csc.repository.entities.OneTimeKeyEntity;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class OneTimeKeysServiceTest {

    @Mock
    KeyRepository<OneTimeKeyEntity> keysRepository;

    @Mock
    SignserverClient signserverClient;

    @Mock
    WorkerRepository workerRepository;

    @InjectMocks
    OneTimeKeysService oneTimeKeysService;


    CryptoToken cryptoToken1 = new CryptoToken("CryptoToken1", 1, List.of());

    @Test
    public void getKeysAcquiredBeforeReturnsNoKeysWhenNonExpiredBefore() {

        // given
        List<OneTimeKeyEntity> keyEntities = new ArrayList<>(); ZonedDateTime before = ZonedDateTime.now();
        given(keysRepository.findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(true, before)).willReturn(keyEntities);

        // when
        var getKeysResult = oneTimeKeysService.getKeysAcquiredBefore(before);

        // then
        List<OneTimeKey> keys = assertSuccessAndGet(getKeysResult); assertEquals(0, keys.size());
    }

    @Test
    public void getKeysAcquiredBeforeReturnsKeysThatExpiredBefore() {
        // given
        ZonedDateTime before = ZonedDateTime.now();
        OneTimeKeyEntity entity = createOneTimekeyEntity("Key1", cryptoToken1.id(), before.minusMinutes(10));
        List<OneTimeKeyEntity> keyEntities = List.of(entity);

        given(keysRepository.findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(true, before)).willReturn(keyEntities);
        given(workerRepository.getCryptoToken(cryptoToken1.id())).willReturn(Result.success(cryptoToken1));

        // when
        var getKeysResult = oneTimeKeysService.getKeysAcquiredBefore(before);

        // then
        List<OneTimeKey> keys = assertSuccessAndGet(getKeysResult); assertEquals(1, keys.size());
        assertSame("Key1", keys.getFirst().keyAlias());
    }

    @Test
    public void getKeysAcquiredBeforeDoesNotReturnKeysWithoutCorrespondingCryptoToken() {
        // given
        ZonedDateTime before = ZonedDateTime.now();
        OneTimeKeyEntity entity = createOneTimekeyEntity("Key1", cryptoToken1.id(), before.minusMinutes(10));
        List<OneTimeKeyEntity> keyEntities = List.of(entity);

        given(keysRepository.findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(true, before)).willReturn(keyEntities);
        given(workerRepository.getCryptoToken(cryptoToken1.id())).willReturn(
                Result.error(TextError.of("CryptoToken not found.")));

        // when
        var getKeysResult = oneTimeKeysService.getKeysAcquiredBefore(before);

        // then
        List<OneTimeKey> keys = assertSuccessAndGet(getKeysResult); assertEquals(0, keys.size());
    }

    @Test
    public void getKeysAcquiredBeforeReturnsErrorWhenFails() {
        // given
        ZonedDateTime before = ZonedDateTime.now();
        given(keysRepository.findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(true, before)).willThrow(
                new RuntimeException("Error"));

        // when
        var getKeysResult = oneTimeKeysService.getKeysAcquiredBefore(before);

        // then
        assertErrorContains(getKeysResult, "error occurred while retrieving keys acquired before");
    }

    private OneTimeKeyEntity createOneTimekeyEntity(String keyAlias, int tokenId, ZonedDateTime acquiredAt) {
        return new OneTimeKeyEntity(UUID.randomUUID(), tokenId, keyAlias, "keyAlgorithm", true, acquiredAt);
    }


}