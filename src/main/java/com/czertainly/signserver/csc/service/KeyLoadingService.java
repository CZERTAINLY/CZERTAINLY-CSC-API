package com.czertainly.signserver.csc.service;

import com.czertainly.signserver.csc.model.signserver.CryptoToken;
import com.czertainly.signserver.csc.signing.PreloadingKeySelector;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class KeyLoadingService {


    private static final Logger logger = LoggerFactory.getLogger(KeyLoadingService.class);
    PreloadingKeySelector keySelector;
    WorkerRepository workerRepository;

    public KeyLoadingService(PreloadingKeySelector keySelector, WorkerRepository workerRepository) {
        this.keySelector = keySelector;
        this.workerRepository = workerRepository;
    }

    @Scheduled(fixedDelay = 60, timeUnit = TimeUnit.SECONDS)
    public void loadKeys() {
        logger.info("Staring periodical preloading of Crypto Token Keys.");
        try {
            List<CryptoToken> cryptoTokens = workerRepository.getAllWorkers().stream()
                                                             .map(worker -> worker.worker().cryptoToken())
                                                             .distinct()
                                                             .toList();
            cryptoTokens.forEach(token -> {
                logger.debug("Preloading keys for Crypto Token {} ({})", token.name(), token.id());
                keySelector.preloadKeysForCryptoToken(token);
            });
        } catch (Exception e) {
            logger.error("Error during preloading of Crypto Token Keys", e);
        }
    }
}
