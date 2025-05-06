package com.czertainly.csc.service.scheduled;

import com.czertainly.csc.common.exceptions.ApplicationException;
import com.czertainly.csc.configuration.keypools.KeyUsageDesignation;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.service.keys.*;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class KeyPoolReplenishTrigger {

    @Autowired
    @Qualifier("keyGenerationExecutor")
    private ExecutorService keyGenerationExecutor;

    private final KeyPoolReplenisher<SessionKey> sessionKeyPoolReplenisher;
    private final KeyPoolReplenisher<OneTimeKey> oneTimeKeyPoolReplenisher;

    public KeyPoolReplenishTrigger(WorkerRepository repository, SessionKeysService sessionKeysService,
                                   OneTimeKeysService oneTimeKeysService) {

        List<CryptoToken> cryptoTokensForSessionSignatures = getCryptoTokensWithDesignatedUsage(
                repository, KeyUsageDesignation.SESSION_SIGNATURE
        );
        sessionKeyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokensForSessionSignatures, sessionKeysService, keyGenerationExecutor);

        List<CryptoToken> cryptoTokensForOneTimeSignatures = getCryptoTokensWithDesignatedUsage(
                repository, KeyUsageDesignation.ONE_TIME_SIGNATURE
        );
        oneTimeKeyPoolReplenisher = new KeyPoolReplenisher<>(cryptoTokensForOneTimeSignatures, oneTimeKeysService, keyGenerationExecutor);
    }

    @Scheduled(fixedDelay = 60, timeUnit = TimeUnit.SECONDS, initialDelay = 0)
    public void replenishSessionPools() {
        sessionKeyPoolReplenisher.replenishPools();
    }

    @Scheduled(fixedDelay = 60, timeUnit = TimeUnit.SECONDS, initialDelay = 5)
    public void replenishOneTimePools() {
        oneTimeKeyPoolReplenisher.replenishPools();
    }

    private static List<CryptoToken> getCryptoTokensWithDesignatedUsage(
            WorkerRepository repository, KeyUsageDesignation keyUsage
    ) {
        return repository.getCryptoTokensWithPools(keyUsage)
                         .consumeError(err -> {
                             throw new ApplicationException(
                                     "Failed to get list of all available crypto tokens for session signatures.");
                         })
                         .unwrap();
    }
}
