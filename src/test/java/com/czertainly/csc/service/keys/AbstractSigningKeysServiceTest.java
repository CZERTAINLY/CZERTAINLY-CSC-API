package com.czertainly.csc.service.keys;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.repository.KeyRepository;
import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AbstractSigningKeysServiceTest {

    @Mock
    KeyRepository<SessionKeyEntity> keysRepository;

    @Mock
    SignserverClient signserverClient;

    @Mock
    WorkerRepository workerRepository;

    @InjectMocks
    SessionKeysService testKeysService;

    @Test
    void getNumberOfUsableKeysReturnsNumberOfKeysReportedByKeysRepository() {
        // given
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1,
                                                  List.of()
        ); // name = cryptoToken1, id = 1, keyPools = [sessionRsa]
        String keyAlgorithm = "RSA";

        when(keysRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(cryptoToken.id(), keyAlgorithm, false))
                .thenReturn(5);

        // when
        var result = testKeysService.getNumberOfUsableKeys(cryptoToken, keyAlgorithm);

        // then
        int numOfUsableKeys = assertSuccessAndGet(result);
        assertEquals(5, numOfUsableKeys);
    }

    @Test
    void getNumberOfUsableKeysReturnsErrorWhenKeysRepositoryThrowsException() {
        // given
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlgorithm = "RSA";

        when(keysRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(cryptoToken.id(), keyAlgorithm, false))
                .thenThrow(new RuntimeException("Some error"));

        // when
        var result = testKeysService.getNumberOfUsableKeys(cryptoToken, keyAlgorithm);

        // then
        assertErrorContains(result, "Couldn't count number of free keys of CryptoToken 'cryptoToken (1)'.");
    }

    @Test
    void generateKeySavesKeyToRepositoryWithAliasReturnedBySignserver() {
        // given
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String initialKeyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        String keySpec = "2048";
        String finalKeyAlias = initialKeyAlias + "-final";

        // A session key entity that will be returned by the repository
        SessionKeyEntity savedKeyEntity = aSessionKeyEntity(cryptoToken, finalKeyAlias, keyAlgorithm);

        when(signserverClient.generateKey(cryptoToken, initialKeyAlias, keyAlgorithm, keySpec))
                .thenReturn(Result.success(finalKeyAlias));

        when(keysRepository.save(any())).thenReturn(savedKeyEntity);

        // when
        var result = testKeysService.generateKey(cryptoToken, initialKeyAlias, keyAlgorithm, keySpec);

        // then
        SessionKey key = assertSuccessAndGet(result);

        assertEquals(finalKeyAlias, key.keyAlias());
        assertEquals(cryptoToken, key.cryptoToken());
        assertEquals(keyAlgorithm, key.keyAlgorithm());
    }

    @Test
    void generateKeyReturnsErrorWhenKeyGenerationFailsOnSignserver() {
        // setup
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        String keySpec = "2048";

        // given
        when(signserverClient.generateKey(cryptoToken, keyAlias, keyAlgorithm, keySpec))
                .thenReturn(Result.error(TextError.of("Foo error")));

        // when
        var result = testKeysService.generateKey(cryptoToken, keyAlias, keyAlgorithm, keySpec);

        // then
        assertErrorContains(result, "Key couldn't be generated on Signserver");
    }

    @Test
    void generateKeyReturnsErrorWhenKeyCantBeSavedToRepository() {
        // given
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        String keySpec = "2048";

        when(signserverClient.generateKey(cryptoToken, keyAlias, keyAlgorithm, keySpec))
                .thenReturn(Result.success(keyAlias));

        when(keysRepository.save(any())).thenThrow(new RuntimeException("Some Foo Error"));

        // when
        var result = testKeysService.generateKey(cryptoToken, keyAlias, keyAlgorithm, keySpec);

        // then
        assertErrorContains(result, "Key couldn't be saved to the database");
    }

//    @Test
//    void acquireKeyReturnsKeyFromRepositoryAndMarksItAsUsed() {
//        // setup
//        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
//        String keyAlgorithm = "RSA";
//
//        var sessionEntity = Mockito.spy(aSessionKeyEntity(cryptoToken, "key-alias", keyAlgorithm));
//
//        when(keysRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(cryptoToken.id(), keyAlgorithm, false))
//                .thenReturn(Optional.of(sessionEntity));
//        when(keysRepository.save(sessionEntity)).thenAnswer(invocation -> invocation.getArgument(0));
//
//        // when
//        var result = testKeysService.acquireKey(cryptoToken, keyAlgorithm);
//
//        // then
//        SessionKey key = assertSuccessAndGet(result);
//        verify(sessionEntity).setAcquiredAt(any());
//        verify(sessionEntity).setInUse(true);
//        assertEquals("key-alias", key.keyAlias());
//        assertEquals(cryptoToken, key.cryptoToken());
//        assertEquals(keyAlgorithm, key.keyAlgorithm());
//        assertEquals(true, key.inUse());
//    }

//    @Test
//    void acquireKeyReturnsErrorWhenNoSuitableKeyIsFound() {
//        // given
//        CryptoToken cryptoToken = new CryptoToken("tokenA", 1, List.of());
//        String keyAlgorithm = "RSA";
//        when(keysRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(1, keyAlgorithm, false))
//                .thenReturn(Optional.empty());
//
//        // when
//        var result = testKeysService.acquireKey(cryptoToken, keyAlgorithm);
//
//        // then
//        assertErrorContains(result, String.format(
//                "New key couldn't be acquired from CryptoToken '%s'.: No KeyPoolProfile found for key algorithm '%s' in CryptoToken '%s'.",
//                cryptoToken.identifier(), keyAlgorithm, cryptoToken.identifier()
//        ));
//    }

    @Test
    void getKeyReturnsKeyAndAssociatedCryptoToken() {
        // given
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";

        SessionKeyEntity sessionKeyEntity = aSessionKeyEntity(cryptoToken, keyAlias, keyAlgorithm);

        when(keysRepository.findById(sessionKeyEntity.getId())).thenReturn(Optional.of(sessionKeyEntity));
        when(workerRepository.getCryptoToken(cryptoToken.id())).thenReturn(Result.success(cryptoToken));

        // when
        var result = testKeysService.getKey(sessionKeyEntity.getId());

        // then
        SessionKey key = assertSuccessAndGet(result);
        assertEquals(keyAlias, key.keyAlias());
        assertEquals(cryptoToken, key.cryptoToken());
        assertEquals(keyAlgorithm, key.keyAlgorithm());
    }

    @Test
    void getKeyReturnsErrorWhenTheKeyWithGivenIdDoesNotExist() {
        // given
        UUID keyId = UUID.randomUUID();
        when(keysRepository.findById(keyId)).thenReturn(Optional.empty());

        // when
        var result = testKeysService.getKey(keyId);

        // then
        assertErrorContains(result, String.format("Signing key with id '%s' does not exist.", keyId));
    }

    @Test
    void getKeyReturnsErrorWhenCryptoTokenCannotBeRetrieved() {
        // setup
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";

        SessionKeyEntity sessionKeyEntity = aSessionKeyEntity(cryptoToken, keyAlias, keyAlgorithm);
        when(keysRepository.findById(sessionKeyEntity.getId())).thenReturn(Optional.of(sessionKeyEntity));

        // given
        when(workerRepository.getCryptoToken(cryptoToken.id())).thenReturn(Result.error(TextError.of("Some error")));

        // when
        var result = testKeysService.getKey(sessionKeyEntity.getId());

        // then
        assertErrorContains(result, String.format("Can't retrieve key with id '%s'", sessionKeyEntity.getId()));
    }

    @Test
    void deleteKeyRemovesKeyFromSignserverAndRepository() {
        // setup
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        SessionKeyEntity sessionKeyEntity = aSessionKeyEntity(cryptoToken, keyAlias, keyAlgorithm);

        when(keysRepository.findById(sessionKeyEntity.getId())).thenReturn(Optional.of(sessionKeyEntity));
        when(workerRepository.getCryptoToken(cryptoToken.id())).thenReturn(Result.success(cryptoToken));
        when(signserverClient.removeKeyOkIfNotExists(cryptoToken.id(), keyAlias)).thenReturn(Result.emptySuccess());

        // when
        var result = testKeysService.deleteKey(sessionKeyEntity.getId());

        // then
        assertSuccessAndGet(result);
        verify(keysRepository).deleteById(sessionKeyEntity.getId());
        verify(signserverClient).removeKeyOkIfNotExists(cryptoToken.id(), keyAlias);
    }

    @Test
    void deleteKeyReturnsErrorIfKeyDoesNotExists() {
        // setup
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        SessionKeyEntity sessionKeyEntity = aSessionKeyEntity(cryptoToken, keyAlias, keyAlgorithm);

        when(keysRepository.findById(sessionKeyEntity.getId())).thenReturn(Optional.empty());

        // when
        var result = testKeysService.deleteKey(sessionKeyEntity.getId());

        // then
        assertErrorContains(result, String.format("Signing key with id '%s' does not exist.", sessionKeyEntity.getId()));
    }

    @Test
    void deleteKeyReturnsErrorIfCryptoTokenAssociatedWithTheKeyDoesNotExist() {
        // setup
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        SessionKeyEntity sessionKeyEntity = aSessionKeyEntity(cryptoToken, keyAlias, keyAlgorithm);

        when(keysRepository.findById(sessionKeyEntity.getId())).thenReturn(Optional.of(sessionKeyEntity));
        when(workerRepository.getCryptoToken(cryptoToken.id())).thenReturn(Result.error(TextError.of("Some error")));
        // when
        var result = testKeysService.deleteKey(sessionKeyEntity.getId());

        // then
        assertErrorContains(result, String.format("Can't delete key with id '%s'.", sessionKeyEntity.getId()));
    }

    @Test
    void deleteKeyReturnsErrorIfKeyCannotBeRemovedFromSignserver() {
        // setup
        CryptoToken cryptoToken = new CryptoToken("cryptoToken", 1, List.of());
        String keyAlias = "key-alias";
        String keyAlgorithm = "RSA";
        SessionKeyEntity sessionKeyEntity = aSessionKeyEntity(cryptoToken, keyAlias, keyAlgorithm);

        when(keysRepository.findById(sessionKeyEntity.getId())).thenReturn(Optional.of(sessionKeyEntity));
        when(workerRepository.getCryptoToken(cryptoToken.id())).thenReturn(Result.success(cryptoToken));
        when(signserverClient.removeKeyOkIfNotExists(cryptoToken.id(), keyAlias))
                .thenReturn(Result.error(TextError.of("Some error")));

        // when
        var result = testKeysService.deleteKey(sessionKeyEntity.getId());

        // then
        assertErrorContains(result, String.format("Key 'key-alias' with id '%s' couldn't be deleted.", sessionKeyEntity.getId()));
    }


    SessionKeyEntity aSessionKeyEntity(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm) {
        return new SessionKeyEntity(UUID.randomUUID(), cryptoToken.id(), keyAlias, keyAlgorithm, false, null);
    }

    SessionKeyEntity aSessionKeyEntity(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm, boolean inUse) {
        if (inUse) {
            return new SessionKeyEntity(UUID.randomUUID(), cryptoToken.id(), keyAlias, keyAlgorithm, true,
                                        ZonedDateTime.now()
            );
        }
        return new SessionKeyEntity(UUID.randomUUID(), cryptoToken.id(), keyAlias, keyAlgorithm, false, null);
    }

}