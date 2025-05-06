package com.czertainly.csc.service.keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class OneTimeKeyAsyncDeletionService {

    private static final Logger logger = LoggerFactory.getLogger(OneTimeKeyAsyncDeletionService.class);

    private final OneTimeKeysService oneTimeKeysService;

    public OneTimeKeyAsyncDeletionService(OneTimeKeysService oneTimeKeysService) {
        this.oneTimeKeysService = oneTimeKeysService;
    }

    @Async("oneTimeKeyDeletionExecutor")
    public void deleteKeyAsync(OneTimeKey key) {
        oneTimeKeysService.deleteKey(key)
                .consumeError(err -> logger.error("Async deletion failed for one-time key '{}': {}", key.keyAlias(), err));
    }
}
