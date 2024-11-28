package com.czertainly.csc.service.keys;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.repository.KeyRepository;
import com.czertainly.csc.repository.entities.OneTimeKeyEntity;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class OneTimeKeysService extends AbstractSigningKeysService<OneTimeKeyEntity, OneTimeKey> {

    public OneTimeKeysService(KeyRepository<OneTimeKeyEntity> keysRepository,
                              SignserverClient signserverClient, WorkerRepository workerRepository
    ) {
        super(keysRepository, signserverClient, workerRepository);
    }

    @Override
    public OneTimeKey mapEntityToSigningKey(OneTimeKeyEntity entity, CryptoToken cryptoToken) {
        return new OneTimeKey(
                entity.getId(),
                cryptoToken,
                entity.getKeyAlias(),
                entity.getKeyAlgorithm(),
                entity.getInUse(),
                entity.getAcquiredAt()
        );
    }

    @Override
    public OneTimeKeyEntity createNewKeyEntity(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm) {
        return new OneTimeKeyEntity(
                UUID.randomUUID(),
                cryptoToken.id(),
                keyAlias,
                keyAlgorithm,
                false,
                null
        );
    }
}
