package com.czertainly.csc.signing;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.service.keys.KeysService;
import com.czertainly.csc.service.keys.SigningKey;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LocalKeySelector<K extends SigningKey> implements KeySelector<K> {

    private static final Logger logger = LoggerFactory.getLogger(LocalKeySelector.class);
    private final KeysService<K> keysService;
    private final WorkerRepository workerRepository;

    public LocalKeySelector(KeysService<K> keysService, WorkerRepository workerRepository) {
        this.keysService = keysService;
        this.workerRepository = workerRepository;
    }

    @Override
    public Result<K, TextError> selectKey(int workerId, String keyAlgorithm) {
        logger.trace("Selecting key with algorithm '{}' connected to worker '{}'.", keyAlgorithm, workerId);
        WorkerWithCapabilities workerWithCapabilities = workerRepository.getWorker(workerId);
        CryptoToken cryptoToken = workerWithCapabilities.worker().cryptoToken();
        return keysService.acquireKey(cryptoToken, keyAlgorithm);
    }

    @Override
    public Result<Void, TextError> markKeyAsUsed(K key) {
        return null;
    }
}
