package com.czertainly.csc.service.keys;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.configuration.keypools.KeyPoolProfile;
import com.czertainly.csc.configuration.keypools.KeyUsageDesignation;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.utils.configuration.KeyPoolProfileBuilder;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KeyPoolReplenisherTest {

    @Mock
    SessionKeysService keysService;

    List<CryptoToken> cryptoTokens = List.of();
    KeyPoolReplenisher<SessionKey> keyPoolReplenisher;

    static ExecutorService directExecutor() {
        return new AbstractExecutorService() {
            @Override public void execute(@NotNull Runnable command) { command.run(); }
            @Override public void shutdown() {}
            @Override public @NotNull List<Runnable> shutdownNow() { return List.of(); }
            @Override public boolean isShutdown() { return true; }
            @Override public boolean isTerminated() { return true; }
            @Override public boolean awaitTermination(long l, @NotNull TimeUnit u) { return true; }
        };
    }

    /* in each test */
    ExecutorService keyGenerationExecutor = directExecutor();

    @Test
    void replenishPoolsReplenishesAllExistingPoolsWhenAssociatedWithSeveralCryptoTokens() {
        // setup
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(0));
        when(keysService.generateKey(any(), any(), any(), any())).thenReturn(Result.success(null));

        // given
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(sessionEcdsaSize1));
        CryptoToken ct2 = new CryptoToken("cryptoToken2", 2, List.of(sessionRsaSize1));

        cryptoTokens = List.of(ct1, ct2);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        // when
        keyPoolReplenisher.replenishPools();

        // then
        verify(keysService, times(2)).generateKey(any(), any(), any(), any());
    }

    @Test
    void replenishPoolsReplenishesAllExistingPoolsWhenAssociatedWithSingleCryptoToken() {
        // setup
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(0));
        when(keysService.generateKey(any(), any(), any(), any())).thenReturn(Result.success(null));

        // given
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(sessionRsaSize1, sessionEcdsaSize1));

        cryptoTokens = List.of(ct1);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        // when
        keyPoolReplenisher.replenishPools();

        // then
        verify(keysService, times(2)).generateKey(any(), any(), any(), any());
    }

    @Test
    void replenishPoolsReplenishesAllKeysWhenPoolEmpty() {
        // setup
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(0));
        when(keysService.generateKey(any(), any(), any(), any())).thenReturn(Result.success(null));

        // given
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(sessionRsaSize5));

        // setup
        cryptoTokens = List.of(ct1);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        // when
        keyPoolReplenisher.replenishPools();

        // then
        verify(keysService, times(5)).generateKey(eq(ct1), contains(sessionRsaSize5.keyPrefix()),
                                                  eq(sessionRsaSize5.keyAlgorithm()),
                                                  eq(sessionRsaSize5.keySpecification())
        );
    }

    @Test
    void replenishPoolsReplenishesOnlyNecessaryAmountOfKeys() {
        // setup
        when(keysService.generateKey(any(), any(), any(), any())).thenReturn(Result.success(null));

        // given
        int numOfFreeKeys = 3;
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(numOfFreeKeys));

        // setup
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(sessionRsaSize5));
        cryptoTokens = List.of(ct1);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        // when
        keyPoolReplenisher.replenishPools();

        // then
        verify(keysService, times(2)).generateKey(eq(ct1), contains(sessionRsaSize5.keyPrefix()),
                                                  eq(sessionRsaSize5.keyAlgorithm()),
                                                  eq(sessionRsaSize5.keySpecification())
        );
    }

    @Test
    void replenishPoolsReplenishesMaximalAmountOfKeysPerReplenishIfMoreThanThatAmountIsNeeded() {
        // setup
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(0));
        when(keysService.generateKey(any(), any(), any(), any())).thenReturn(Result.success(null));

        // given
        KeyPoolProfile profile = profileRequires10Max2PerReplenish;

        // setup
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(profile));
        cryptoTokens = List.of(ct1);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        // when
        keyPoolReplenisher.replenishPools();

        // then
        verify(keysService, times(2)).generateKey(eq(ct1), contains(profile.keyPrefix()), eq(profile.keyAlgorithm()),
                                                  eq(profile.keySpecification())
        );
    }

    @Test
    void replenishPoolsDoesNotThrowErrorWhenCantObtainNumberOfUsableKeys() {
        // setup
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(sessionRsaSize1));
        cryptoTokens = List.of(ct1);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        //given
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.error(TextError.of("error")));

        // when
        Executable e = () -> keyPoolReplenisher.replenishPools();

        // then
        assertDoesNotThrow(e);
    }

    @Test
    void replenishPoolsStopsReplenishingThePoolWhenSomeKeyCantBeGenerated() {
        // setup
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(0));
        KeyPoolProfile profile = sessionRsaSize5;
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(profile));
        cryptoTokens = List.of(ct1);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        //given

        when(keysService.generateKey(any(), any(), any(), any())).thenReturn(Result.error(TextError.of("error")));

        // when
        keyPoolReplenisher.replenishPools();

        // then
        // 5 keys wanted, all key generation attempts are made concurrently regardless of failures
        verify(keysService, times(5))
                .generateKey(eq(ct1), contains(profile.keyPrefix()),
                        eq(profile.keyAlgorithm()), eq(profile.keySpecification()));
    }

    @Test
    void replenishPoolsKeepsReplenishingOtherPoolsWhenReplenishingOfOneFails() {
        // setup
        when(keysService.getNumberOfUsableKeys(any(), any())).thenReturn(Result.success(0));
        KeyPoolProfile profile = sessionRsaSize5;
        CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(profile));
        CryptoToken ct2 = new CryptoToken("cryptoToken2", 2, List.of(profile));
        cryptoTokens = List.of(ct1, ct2);
        keyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokens, keysService, keyGenerationExecutor);

        //given
        when(keysService.generateKey(eq(ct1), any(), any(), any())).thenReturn(Result.error(TextError.of("error")));
        when(keysService.generateKey(eq(ct2), any(), any(), any())).thenReturn(Result.success(null));

        // when
        keyPoolReplenisher.replenishPools();

        // then

        // 5 keys  generated for CryptoToken2
        verify(keysService, times(5)).generateKey(eq(ct2), any(), any(), any());
    }

    KeyPoolProfile sessionRsaSize1 = KeyPoolProfileBuilder.create().withName("session_rsa").withKeyAlgorithm("RSA")
                                                          .withDesiredSize(1)
                                                          .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                          .build();

    KeyPoolProfile sessionRsaSize5 = KeyPoolProfileBuilder.create().withName("session_rsa").withKeyAlgorithm("RSA")
                                                          .withDesiredSize(5)
                                                          .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                          .build();

    KeyPoolProfile profileRequires10Max2PerReplenish = KeyPoolProfileBuilder.create().withName("session_rsa")
                                                                            .withKeyAlgorithm("RSA").withDesiredSize(5)
                                                                            .withMaxKeysGeneratedPerReplenish(2)
                                                                            .withDesignatedUsage(
                                                                                    KeyUsageDesignation.SESSION_SIGNATURE)
                                                                            .build();

    KeyPoolProfile sessionEcdsaSize1 = KeyPoolProfileBuilder.create().withName("session_ecdsa")
                                                            .withKeyAlgorithm("ECDSA").withDesiredSize(1)
                                                            .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                            .build();

}