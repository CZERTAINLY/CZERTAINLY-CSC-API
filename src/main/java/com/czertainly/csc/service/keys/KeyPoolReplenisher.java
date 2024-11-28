package com.czertainly.csc.service.keys;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.configuration.keypools.KeyPoolProfile;
import com.czertainly.csc.model.signserver.CryptoToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class KeyPoolReplenisher<K extends SigningKey> {

    private static final Logger logger = LoggerFactory.getLogger(KeyPoolReplenisher.class);
    private final KeysService<K> keysService;
    private final List<CryptoToken> cryptoTokens;

    public KeyPoolReplenisher(List<CryptoToken> cryptoTokens, KeysService<K> keysService) {
        this.keysService = keysService;
        this.cryptoTokens = cryptoTokens;
    }

    public void replenishPools() {
        for (CryptoToken cryptoToken : cryptoTokens) {
            for (KeyPoolProfile keyPoolProfile : cryptoToken.keyPoolProfiles()) {
                keysService.getNumberOfUsableKeys(cryptoToken, keyPoolProfile.keyAlgorithm())
                           .flatMap(numOfFreeKeys -> replenishPool(cryptoToken, keyPoolProfile, numOfFreeKeys))
                           .consume(numberOfKeysGenerated -> logger.debug(
                                   "Replenished Key Pool of CryptoToken '{}' with algorithm '{}' and usage '{}'. Generated {} new keys.",
                                   cryptoToken.name(), keyPoolProfile.keyAlgorithm(),
                                   keyPoolProfile.designatedUsage(), numberOfKeysGenerated
                           ))
                           .consumeError(error ->
                                                 logger.error(
                                                         "Failed to replenish Key Pool of CryptoToken '{}'  with algorithm '{}' and usage '{}'. {}",
                                                         cryptoToken.name(), keyPoolProfile.keyAlgorithm(),
                                                         keyPoolProfile.designatedUsage(), error.getErrorText()
                                                 )
                           );
            }
        }
    }

    private Result<Integer, TextError> replenishPool(CryptoToken cryptoToken, KeyPoolProfile keyPoolProfile,
                                                     int currentPoolSize
    ) {
        if (currentPoolSize >= keyPoolProfile.desiredSize()) {
            logger.trace("Key pool of CryptoToken '{}' with algorithm '{}' and usage '{}' is up to its desired size.",
                         cryptoToken.name(), keyPoolProfile.keyAlgorithm(), keyPoolProfile.designatedUsage()
            );
            return Result.success(0);
        }
        int numOfKeysNeeded = keyPoolProfile.desiredSize() - currentPoolSize;
        int numOfKeysToGenerate = numOfKeysNeeded;
        if (numOfKeysNeeded > keyPoolProfile.maxKeysGeneratedPerReplenish()) {
            numOfKeysToGenerate = keyPoolProfile.maxKeysGeneratedPerReplenish();
            logger.trace(
                    "Key pool of CryptoToken '{}' with algorithm '{}' and usage '{}' will be replenished by {} keys (maximal number of keys generated per replenish).",
                    cryptoToken.name(), keyPoolProfile.keyAlgorithm(), keyPoolProfile.desiredSize(),
                    numOfKeysToGenerate
            );
        } else {
            logger.trace(
                    "Key pool of CryptoToken '{}' with algorithm '{}' and usage '{}' will be replenished by {} keys to its desired size {}.",
                    cryptoToken.name(), keyPoolProfile.keyAlgorithm(), keyPoolProfile.desiredSize(),
                    numOfKeysToGenerate, keyPoolProfile.desiredSize()
            );
        }

        for (int i = 0; i < numOfKeysToGenerate; i++) {
            logger.info("Replenishing key pool of CryptoToken '{}' with algorithm '{}' and usage '{}'.",
                        cryptoToken.name(),
                        keyPoolProfile.keyAlgorithm(), keyPoolProfile.designatedUsage()
            );
            String keyAlias = getUniqueKeyAlias(keyPoolProfile.keyPrefix());
            var generateKeyResult = keysService.generateKey(
                                                       cryptoToken, keyAlias, keyPoolProfile.keyAlgorithm(),
                                                       keyPoolProfile.keySpecification()
                                               )
                                               .mapError(error -> error.extend(
                                                                 "Generation of a key '%s' for key poll of CryptoToken '%s' has failed.",
                                                                 keyAlias, cryptoToken.name()
                                                         )
                                               )
                                               .consumeError(error -> logger.error(error.getErrorText()));
            if (generateKeyResult instanceof Error(var err)) {
                return Result.error(err.extend("Pool only replenished with %d keys.", i));
            }

        }
        return Result.success(numOfKeysToGenerate);
    }

    private String getUniqueKeyAlias(String userId) {
        String random_id = RandomStringUtils.secure().next(8, true, true);
        String alias = String.format("%s-%s", userId, random_id);
        logger.trace("Generated new unique key alias {}", alias);
        return alias;
    }
}
