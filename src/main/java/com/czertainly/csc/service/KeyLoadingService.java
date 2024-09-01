package com.czertainly.csc.service;

import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.signing.PreloadingKeySelector;
import com.czertainly.csc.signing.configuration.WorkerRepository;
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
        logger.info("Starting periodical preloading of Crypto Token Keys.");
            workerRepository
                    .getAllCryptoTokens()
                    .mapError(error -> error.extend("Failed to get list of all available crypto tokens."))
                    .consume(cryptoTokens -> cryptoTokens.forEach(token -> {
                        logger.debug("Preloading keys for Crypto Token {} ({})", token.name(), token.id());
                        keySelector.preloadKeysForCryptoToken(token)
                                .consumeError(error -> logger.error("Failed to preload keys for Crypto Token {}({}). {}", token.name(), token.id(), error));
                    }))
                    .consumeError(error -> logger.error("Failed to preload Sign server keys. {}", error));
    }
}
