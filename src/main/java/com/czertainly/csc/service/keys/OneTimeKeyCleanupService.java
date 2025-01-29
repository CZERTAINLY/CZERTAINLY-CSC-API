package com.czertainly.csc.service.keys;

import com.czertainly.csc.configuration.csc.CscConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.ZonedDateTime;

@Component
public class OneTimeKeyCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(OneTimeKeyCleanupService.class);
    private final OneTimeKeysService oneTimeKeysService;
    private final Duration usedUpKeysKeepTime;

    public OneTimeKeyCleanupService(OneTimeKeysService oneTimeKeysService, CscConfiguration cscConfiguration) {
        this.oneTimeKeysService = oneTimeKeysService;
        this.usedUpKeysKeepTime = cscConfiguration.oneTimeKeys().usedUpKeyKeepTime();
    }

    public void cleanUsedUpKeys() {
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime before = now.minus(usedUpKeysKeepTime);
        oneTimeKeysService.getKeysAcquiredBefore(before)
                          .consume(expiredKeys -> {
                              logger.info("Found {} one-time keys for cleanup", expiredKeys.size());
                              for (OneTimeKey expired : expiredKeys) {
                                  oneTimeKeysService
                                          .deleteKey(expired)
                                          .consumeError(err -> logger.error(
                                                                "An error occurred while deleting used one-time key '{}'. {}",
                                                                expired.keyAlias(), err
                                                        )
                                          );
                              }
                          })
                          .consumeError(
                                  err -> logger.error(
                                          "An error occurred while cleaning up used one-time keys. {}", err)
                          );
    }
}
