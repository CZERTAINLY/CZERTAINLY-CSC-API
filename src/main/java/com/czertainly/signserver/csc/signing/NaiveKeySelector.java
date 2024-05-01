package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.common.exceptions.ApplicationException;
import com.czertainly.signserver.csc.model.signserver.CryptoTokenKey;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

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
        List<CryptoTokenKey> keys = signserverClient.queryCryptoTokenKeys(cryptoToken.id(), true, 0, 50);
        if (keys.isEmpty()) {
            throw new ApplicationException(
                    "No pre-generated key is available in CryptoToken " + cryptoToken.name() + " used by worker " + workerId);
        }
        CryptoTokenKey key = keys.stream()
                                 .filter(k -> k.status() != null && !k.status().certified())
                                 .findFirst()
                                 .orElse(null);

        if (key == null) {
            throw new ApplicationException(
                    "Non of the loaded pre-generated keys from CryptoToken " + cryptoToken.name() + " used by worker " + workerId
                            + " is available for signing.");
        }
        return key;
    }
}
