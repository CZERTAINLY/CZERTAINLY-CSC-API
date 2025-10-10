package com.czertainly.csc.service.keys;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.configuration.keypools.KeyUsageDesignation;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.repository.KeyRepository;
import com.czertainly.csc.repository.entities.SessionKeyEntity;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.UUID;

@Component
public class SessionKeysService extends AbstractSigningKeysService<SessionKeyEntity, SessionKey> {

    public SessionKeysService(KeyRepository<SessionKeyEntity> keysRepository,
                              SignserverClient signserverClient, WorkerRepository workerRepository,
                              TransactionTemplate transactionTemplate
    ) {
        super(keysRepository, signserverClient, workerRepository, transactionTemplate);
    }

    @Override
    public SessionKey mapEntityToSigningKey(SessionKeyEntity entity, CryptoToken cryptoToken) {
        return new SessionKey(
                entity.getId(),
                cryptoToken,
                entity.getKeyAlias(),
                entity.getKeyAlgorithm(),
                entity.getInUse(),
                entity.getAcquiredAt()
        );
    }

    @Override
    public SessionKeyEntity createNewKeyEntity(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm) {
        return new SessionKeyEntity(
                UUID.randomUUID(),
                cryptoToken.id(),
                keyAlias,
                keyAlgorithm,
                false,
                null
        );
    }

    @Override
    public KeyUsageDesignation getKeyUsageDesignation() {
        return KeyUsageDesignation.SESSION_SIGNATURE;
    }
}
