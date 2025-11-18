package com.czertainly.csc.service.keys;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.configuration.keypools.KeyUsageDesignation;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.repository.LongTermKeyRepository;
import com.czertainly.csc.repository.entities.LongTermKeyEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

@Component
public class LongTermKeysService implements KeysService<LongTermKey> {

    private static final Logger logger = LoggerFactory.getLogger(LongTermKeysService.class);

    private final LongTermKeyRepository keysRepository;
    private final SignserverClient signserverClient;
    private final TransactionTemplate transactionTemplate;

    // ReentrantLock per crypto token ID to prevent duplicate key generation while allowing virtual threads to unmount
    private static final ConcurrentHashMap<Integer, ReentrantLock> cryptoTokenLocks = new ConcurrentHashMap<>();

    public LongTermKeysService(LongTermKeyRepository keysRepository,
                               SignserverClient signserverClient, TransactionTemplate transactionTemplate
    ) {

        this.keysRepository = keysRepository;
        this.signserverClient = signserverClient;
        this.transactionTemplate = transactionTemplate;
    }

    @Override
    public Result<Integer, TextError> getNumberOfUsableKeys(CryptoToken cryptoToken, String keyAlgorithm) {
        logger.debug("Counting free keys of CryptoToken '{}' with key algorithm '{}'", cryptoToken.identifier(),
                     keyAlgorithm
        );
        try {
            int numOfFreeKeys = keysRepository.countByCryptoTokenIdAndKeyAlgorithm(cryptoToken.id(), keyAlgorithm);
            return Result.success(numOfFreeKeys);
        } catch (Exception e) {
            logger.error("Couldn't count number of free keys of CryptoToken '{}' with key algorithm '{}'.",
                         cryptoToken.identifier(), keyAlgorithm, e
            );
            return Result.error(TextError.of(
                    "Couldn't count number of free keys of CryptoToken '%s'.",
                    cryptoToken.identifier()
            ));
        }
    }

    @Override
    public Result<LongTermKey, TextError> generateKey(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm,
                                                      String keySpec
    ) {
        logger.debug("Generating a new key for CryptoToken '{}' with alias '{}', algorithm '{}' and key spec '{}'",
                     cryptoToken.identifier(), keyAlias, keyAlgorithm, keySpec
        );
        return signserverClient.generateKey(cryptoToken, keyAlias, keyAlgorithm, keySpec)
                               .mapError(e -> e.extend(
                                       "Key couldn't be generated on Signserver CryptoToken '%s'.",
                                       cryptoToken.identifier()
                               ))
                               .flatMap(finalKeyAlias -> saveKey(cryptoToken, finalKeyAlias, keyAlgorithm))
                               .map(keyEntity -> this.mapEntityToSigningKey(keyEntity, cryptoToken));
    }

    @Override
    public Result<LongTermKey, TextError> acquireKey(CryptoToken cryptoToken, String keyAlgorithm) {
        logger.debug("Acquiring a signing key of CryptoToken '{}' with algorithm '{}'",
                     cryptoToken.identifier(), keyAlgorithm
        );
        // Use ReentrantLock instead of synchronized to allow virtual threads to unmount during blocking I/O
        ReentrantLock lock = cryptoTokenLocks.computeIfAbsent(cryptoToken.id(), id -> new ReentrantLock());
        lock.lock();

        try {
            // Execute database operations inside a transaction, but only after acquiring the lock
            // This ensures threads wait for the lock WITHOUT holding a database connection
            return acquireKeyAndDeleteInTransaction(cryptoToken, keyAlgorithm)
                    .flatMap(key ->
                                     key.map(acquiredKey -> {
                                         logger.info("Signing key acquired for CryptoToken '{}' with algorithm '{}'. Key alias: '{}'",
                                                     cryptoToken.identifier(), keyAlgorithm, acquiredKey.keyAlias()
                                         );
                                         return Result.<LongTermKey, TextError>success(acquiredKey);
                                     }).orElseGet(() -> {
                                         logger.debug(
                                                 "No Signing key found for CryptoToken '{}' with algorithm '{}'. Will generate a new one on the fly.",
                                                 cryptoToken.identifier(), keyAlgorithm
                                         );
                                         return findKeyProfileAndGenerateKeyOnSignserver(cryptoToken, keyAlgorithm)
                                                 .map(alias -> new LongTermKey(
                                                         UUID.randomUUID(),
                                                         cryptoToken,
                                                         alias,
                                                         keyAlgorithm
                                                 ))
                                                 .mapError(e -> e.extend(
                                                         "Couldn't generate a new signing key for CryptoToken '%s.",
                                                         cryptoToken.identifier()
                                                 ));
                                     })
                    );
        } catch (Exception e) {
            logger.error(
                    "An exception occurred while acquiring a signing key for CryptoToken '{}' with algorithm '{}'.",
                    cryptoToken.identifier(), keyAlgorithm, e
            );
            return Result.error(
                    TextError.of(
                            "Transaction failed while acquiring a signing key for Crypto Token '%s'.",
                            cryptoToken.identifier()
                    )
            );
        } finally {
            lock.unlock();
        }
    }

    @Override
    public Result<Void, TextError> deleteKey(LongTermKey key) {
        logger.debug("Deleting key '{}' with id '{}'", key.keyAlias(), key.id());

        try {
            keysRepository.deleteById(key.id());
        } catch (Exception e) {
            logger.error("Failed to delete signing key '{}' with id '{}' from database.",
                         key.keyAlias(), key.id(), e
            );
            return Result.error(
                    TextError.of("Key '%s' not deleted from database.", key.keyAlias()));
        }
        return Result.emptySuccess();
    }

    @Override
    public KeyUsageDesignation getKeyUsageDesignation() {
        return KeyUsageDesignation.LONG_TERM_SIGNATURE;
    }

    private Result<LongTermKeyEntity, TextError> saveKey(CryptoToken cryptoToken, String keyAlias,
                                                         String keyAlgorithm
    ) {
        LongTermKeyEntity newEntity = createNewKeyEntity(cryptoToken, keyAlias, keyAlgorithm);
        try {
            logger.debug("Saving new signing key '{}' to the database.", newEntity.getId());
            logger.trace("Signing key: {}", newEntity);
            LongTermKeyEntity savedEntity = keysRepository.save(newEntity);
            logger.info("New signing key '{}' was saved to the database.", savedEntity.getId());
            return Result.success(savedEntity);
        } catch (Exception e) {
            logger.error("Signing key couldn't be saved to the database.", e);
            return Result.error(new TextError("Key couldn't be saved to the database."));
        }
    }

    private Result<Optional<LongTermKey>, TextError> acquireKeyAndDeleteInTransaction(CryptoToken cryptoToken,
                                                                                      String keyAlgorithm
    ) {
        return transactionTemplate.execute(status -> {
            try {
                Optional<LongTermKey> key = keysRepository.findFirstByCryptoTokenIdAndKeyAlgorithm(
                                                                  cryptoToken.id(), keyAlgorithm)
                                                          .map(entity ->
                                                                       this.mapEntityToSigningKey(entity, cryptoToken)
                                                          );
                key.ifPresent(longTermKey -> keysRepository.deleteById(longTermKey.id()));
                return Result.success(key);
            } catch (Exception e) {
                status.setRollbackOnly();
                logger.error(
                        "Couldn't acquire a signing key of CryptoToken '{}' with algorithm '{}'.",
                        cryptoToken.identifier(), keyAlgorithm, e
                );
                return Result.error(
                        TextError.of("Couldn't acquire a signing key of CryptoToken '%s'.", cryptoToken.identifier())
                );
            }
        });
    }

    private Result<String, TextError> findKeyProfileAndGenerateKeyOnSignserver(CryptoToken cryptoToken,
                                                                               String keyAlgorithm
    ) {
        // Select the first KeyPoolProfile that matches the key algorithm and designated usage.
        // If no KeyPoolProfile is found, return Result with an error.
        return cryptoToken.keyPoolProfiles().stream()
                          .filter(kpp -> kpp.keyAlgorithm()
                                            .equals(keyAlgorithm) && kpp.designatedUsage() == this.getKeyUsageDesignation())
                          .findFirst()
                          .map(kpp -> {
                              String keyAlias = String.format("%s-%s", kpp.keyPrefix(), UUID.randomUUID());
                              return signserverClient.generateKey(cryptoToken, keyAlias, keyAlgorithm,
                                                                  kpp.keySpecification()
                              );
                          })
                          .orElseGet(() -> {
                              logger.error(
                                      "No KeyPoolProfile found for key algorithm '{}' in CryptoToken '{}' and usage '{}'.",
                                      keyAlgorithm, cryptoToken.identifier(), this.getKeyUsageDesignation()
                              );
                              return Result.error(TextError.of(
                                                          "No KeyPoolProfile found for key algorithm '%s' in CryptoToken '%s' and usage  '%s'.",
                                                          keyAlgorithm, cryptoToken.identifier(), this.getKeyUsageDesignation()
                                                  )
                              );
                          });
    }

    private LongTermKey mapEntityToSigningKey(LongTermKeyEntity entity, CryptoToken cryptoToken) {
        return new LongTermKey(
                entity.getId(),
                cryptoToken,
                entity.getKeyAlias(),
                entity.getKeyAlgorithm()
        );
    }

    private LongTermKeyEntity createNewKeyEntity(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm) {
        return new LongTermKeyEntity(
                UUID.randomUUID(),
                cryptoToken.id(),
                keyAlias,
                keyAlgorithm
        );
    }
}
