package com.czertainly.csc.signing;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.exceptions.ApplicationException;
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
    SignserverClient signserverClient;
    WorkerRepository workerRepository;
    Map<Integer, ConcurrentLinkedQueue<CryptoTokenKey>> cryptoTokensKeys;
    Set<CryptoTokenKey> keysInUse;

    public PreloadingKeySelector(SignserverClient signserverClient, WorkerRepository workerRepository,
                                 @Value("${csc.numberOfPreloadedKeys}") int maxNumberOfPreloadedKeys
    ) {
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
        this.maxNumberOfPreloadedKeys = maxNumberOfPreloadedKeys;
        cryptoTokensKeys = new HashMap<>();
        keysInUse = ConcurrentHashMap.newKeySet();
    }

    @Override
    public CryptoTokenKey selectKey(int workerId) {
        var workerWithCapabilities = workerRepository.getWorker(workerId);
        var cryptoToken = workerWithCapabilities.worker().cryptoToken();
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
        keysInUse.remove(key);
    }

    public void preloadKeysForCryptoToken(CryptoToken cryptoToken) {
        Queue<CryptoTokenKey> existingKeys = cryptoTokensKeys.computeIfAbsent(
                cryptoToken.id(),
                k -> new ConcurrentLinkedQueue<>()
        );
        synchronized (existingKeys) {
            if (existingKeys.size() >= maxNumberOfPreloadedKeys) {
                return;
            }

            Set<String> existingKeysAliases = existingKeys.stream()
                                                          .map(CryptoTokenKey::keyAlias)
                                                          .collect(Collectors.toSet());
            int numberOfExistingKeys = existingKeys.size();
            int numberOfNewKeys = maxNumberOfPreloadedKeys - numberOfExistingKeys;

            List<CryptoTokenKey> newKeys = signserverClient.queryCryptoTokenKeys(
                    cryptoToken.id(),
                    true,
                    numberOfExistingKeys,
                    numberOfNewKeys
            );
            if (newKeys.isEmpty()) {
                logger.warn("No more pre-generated keys are available in CryptoToken {}", cryptoToken.name());
            } else if (newKeys.size() < numberOfNewKeys) {
                logger.warn("Only {} pre-generated keys are available in CryptoToken {} instead of requested {}." +
                                    " SignServer key generation service may not be keeping up with the key consumption.",
                            newKeys.size(), cryptoToken.name(), numberOfNewKeys
                );
            }
            newKeys.stream()
                   .filter(k -> k.status() != null && !k.status().certified())
                   .filter(k -> !existingKeysAliases.contains(k.keyAlias()))
                   .filter(k -> !keysInUse.contains(k))
                   .forEach(existingKeys::add);
        }
    }
}