package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.model.signserver.CryptoTokenKey;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class NaiveKeySelector implements KeySelector {

    private static final Logger logger = LoggerFactory.getLogger(NaiveKeySelector.class);

    SignserverClient signserverClient;
    WorkerRepository workerRepository;

    public NaiveKeySelector(SignserverClient signserverClient, WorkerRepository workerRepository) {
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
    }

    @Override
    public CryptoTokenKey selectKey(int workerId) {
        var workerWithCapabilities = workerRepository.getWorker(workerId);
        var cryptoToken = workerWithCapabilities.worker().cryptoToken();
        var result = signserverClient.queryCryptoTokenKeys(cryptoToken.id(), true, 0, 5);
        return result.with(
                keys -> keys.stream().filter(key -> !key.status().certified()).findFirst().orElse(null),
                error -> {
                    logger.warn("Unable to select a suitable key: " + error.description());
                    return null;
                }
        );
    }
}
