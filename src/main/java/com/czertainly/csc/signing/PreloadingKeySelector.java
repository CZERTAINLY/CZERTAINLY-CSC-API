package com.czertainly.csc.signing;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.exceptions.ApplicationException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;

@Component
public class PreloadingKeySelector implements KeySelector {

    private static final Logger logger = LoggerFactory.getLogger(PreloadingKeySelector.class);

    private final int maxNumberOfPreloadedKeys;
    private final String keyAliasFilterPattern;
    SignserverClient signserverClient;
    WorkerRepository workerRepository;
    Map<Integer, ConcurrentLinkedQueue<CryptoTokenKey>> cryptoTokensKeys;
    Set<CryptoTokenKey> keysInUse;

    public PreloadingKeySelector(SignserverClient signserverClient, WorkerRepository workerRepository,
                                 @Value("${csc.numberOfPreloadedKeys}") int maxNumberOfPreloadedKeys,
                                 @Value("${csc.keyAliasFilterPattern}") String keyAliasFilterPattern
    ) {
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
        this.maxNumberOfPreloadedKeys = maxNumberOfPreloadedKeys;
        this.keyAliasFilterPattern = keyAliasFilterPattern;
        cryptoTokensKeys = new HashMap<>();
        keysInUse = ConcurrentHashMap.newKeySet();
    }

    @Override
    public CryptoTokenKey selectKey(int workerId) {
        var workerWithCapabilities = workerRepository.getWorker(workerId);
        var cryptoToken = workerWithCapabilities.worker().cryptoToken();
        logger.debug("Will select key for worker {} from CryptoToken {}", workerId, cryptoToken.name());
        Queue<CryptoTokenKey> keys = cryptoTokensKeys.get(cryptoToken.id());
        if (keys == null || keys.isEmpty()) {
            preloadKeysForCryptoToken(cryptoToken);
            keys = cryptoTokensKeys.get(cryptoToken.id());
        }
        CryptoTokenKey key = keys.poll();
        if (key == null) {
            throw new ApplicationException(
                    "No pre-generated keys are available for signing for CryptoToken " + cryptoToken.name() + " used by worker "
                            + workerId);
        }
        keysInUse.add(key);
        return key;
    }

    public void markKeyAsUsed(CryptoTokenKey key) {
        logger.debug("Deleting key in use {}", key.keyAlias());
        keysInUse.remove(key);
    }

    public Result<Void, TextError> preloadKeysForCryptoToken(CryptoToken cryptoToken) {
        logger.debug("Preloading keys for CryptoToken {}", cryptoToken.name());
        Queue<CryptoTokenKey> existingKeys = cryptoTokensKeys.computeIfAbsent(
                cryptoToken.id(),
                k -> new ConcurrentLinkedQueue<>()
        );
        synchronized (existingKeys) {
            if (existingKeys.size() >= maxNumberOfPreloadedKeys) {
                logger.debug(
                        "Has reached or exceeded max number of preloaded keys {}/{} for CryptoToken {}. No more will be preloaded.",
                        existingKeys.size(), maxNumberOfPreloadedKeys, cryptoToken.name()
                );
                return Result.emptySuccess();
            }

            Set<String> existingKeysAliases = existingKeys.stream()
                                                          .map(CryptoTokenKey::keyAlias)
                                                          .collect(Collectors.toSet());
            logger.trace("Existing keys for CryptoToken {}: {}", cryptoToken.name(), existingKeysAliases);
            int numberOfExistingKeys = existingKeys.size();
            int numberOfNewKeys = maxNumberOfPreloadedKeys - numberOfExistingKeys;

            return signserverClient
                    .queryCryptoTokenKeys(cryptoToken.id(), true, numberOfExistingKeys, numberOfNewKeys,
                                          keyAliasFilterPattern
                    )
                    .runIf(List::isEmpty,
                           () -> logger.warn("No more pre-generated keys is available in CryptoToken {}",
                                             cryptoToken.name()
                           )
                    )
                    .runIf(
                            keys -> keys.size() < numberOfNewKeys,
                            (keys) -> logger.warn(
                                    "Only {} of pre-generated keys is available in CryptoToken {} instead of requested {}." +
                                            " SignServer key generation service may not be keeping up with the key consumption.",
                                    keys.size(), cryptoToken.name(), numberOfNewKeys
                            )
                    )
                    .consume(newKeys -> {
                        newKeys.stream()
                               .filter(k -> k.status() == null || !k.status().certified())
                               .filter(k -> {
                                   boolean alreadyExists = existingKeysAliases.contains(k.keyAlias());
                                   if (logger.isTraceEnabled() && alreadyExists) {
                                       logger.trace("Key {} already exists in preloaded keys for CryptoToken {}",
                                                    k.keyAlias(),
                                                    cryptoToken.name()
                                       );
                                   }
                                   return !alreadyExists;
                               })
                               .filter(k -> {
                                   boolean alreadyInUse = keysInUse.contains(k);
                                   if (logger.isTraceEnabled() && alreadyInUse) {
                                       logger.trace("Key {} is already in use", k.keyAlias());
                                   }
                                   return !alreadyInUse;
                               })
                               .forEach(keys -> {
                                   if (logger.isTraceEnabled()) {
                                       logger.trace("Adding key {} to preloaded keys for CryptoToken {}",
                                                    keys.keyAlias(),
                                                    cryptoToken.name()
                                       );
                                   }
                                   existingKeys.add(keys);
                               });
                    })
                    .flatMap((v) -> Result.emptySuccess());
        }
    }
}