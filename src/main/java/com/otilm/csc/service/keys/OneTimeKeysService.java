package com.otilm.csc.service.keys;

import com.otilm.csc.clients.signserver.SignserverClient;
import com.otilm.csc.common.result.Error;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.configuration.keypools.KeyUsageDesignation;
import com.otilm.csc.model.signserver.CryptoToken;
import com.otilm.csc.repository.KeyRepository;
import com.otilm.csc.repository.entities.OneTimeKeyEntity;
import com.otilm.csc.signing.configuration.WorkerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class OneTimeKeysService extends AbstractSigningKeysService<OneTimeKeyEntity, OneTimeKey> {

    private static final Logger logger = LoggerFactory.getLogger(OneTimeKeysService.class);

    public OneTimeKeysService(KeyRepository<OneTimeKeyEntity> keysRepository,
                              SignserverClient signserverClient, WorkerRepository workerRepository,
                              TransactionTemplate transactionTemplate
    ) {
        super(keysRepository, signserverClient, workerRepository, transactionTemplate);
    }

    public Result<List<OneTimeKey>, TextError> getKeysAcquiredBefore(ZonedDateTime before) {
        try {
            List<OneTimeKeyEntity> keyEntities = keysRepository.findByInUseAndAcquiredAtBeforeOrderByAcquiredAtAsc(true,
                                                                                                                   before
            );

            List<OneTimeKey> keys = new ArrayList<>();
            for (OneTimeKeyEntity keyEntity : keyEntities) {
                var getCryptoTokenResult = workerRepository.getCryptoToken(keyEntity.getCryptoTokenId());
                if (getCryptoTokenResult instanceof Error(var err)) {
                    logger.error(
                            "Failed to get CryptoToken '{}'. Key '{}' can't be added to a list of keys for deletion. '{}'",
                            keyEntity.getCryptoTokenId(), keyEntity.getKeyAlias(), err
                    );
                    continue;
                }
                CryptoToken cryptoToken = getCryptoTokenResult.unwrap();
                keys.add(mapEntityToSigningKey(keyEntity, cryptoToken));
            }
            return Result.success(keys);
        } catch (Exception e) {
            logger.error("An error occurred while retrieving keys acquired before '{}'.", before, e);
            return Result.error(TextError.of("An error occurred while retrieving keys acquired before '%s'.", before));
        }
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

    @Override
    public KeyUsageDesignation getKeyUsageDesignation() {
        return KeyUsageDesignation.ONE_TIME_SIGNATURE;
    }
}
