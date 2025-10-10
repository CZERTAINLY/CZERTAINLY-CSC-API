package com.czertainly.csc.service.keys;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.repository.KeyRepository;
import com.czertainly.csc.repository.entities.KeyEntity;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Allows to generate new signing keys on Signserver and stores them in database.
 * Also allows to acquire the key for signature.
 */
@Service
public abstract class AbstractSigningKeysService<E extends KeyEntity, K extends SigningKey> implements KeysService<K> {

    private static final Logger logger = LoggerFactory.getLogger(AbstractSigningKeysService.class);
    protected final KeyRepository<E> keysRepository;
    private final SignserverClient signserverClient;
    protected final WorkerRepository workerRepository;
    private final TransactionTemplate transactionTemplate;

    // ReentrantLock per crypto token ID to prevent duplicate key generation while allowing virtual threads to unmount
    private static final ConcurrentHashMap<Integer, ReentrantLock> cryptoTokenLocks = new ConcurrentHashMap<>();


    public AbstractSigningKeysService(KeyRepository<E> keysRepository, SignserverClient signserverClient,
                                      WorkerRepository workerRepository, TransactionTemplate transactionTemplate
    ) {
        this.keysRepository = keysRepository;
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
        this.transactionTemplate = transactionTemplate;
    }

    @Override
    public Result<Integer, TextError> getNumberOfUsableKeys(CryptoToken cryptoToken, String keyAlgorithm) {
        logger.debug("Counting free keys of CryptoToken '{}' with key algorithm '{}'", cryptoToken.identifier(),
                     keyAlgorithm
        );
        try {
            int numOfFreeKeys = keysRepository.countByCryptoTokenIdAndKeyAlgorithmAndInUse(
                    cryptoToken.id(), keyAlgorithm, false
            );
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
    public Result<K, TextError> generateKey(
            CryptoToken cryptoToken, String keyAlias, String keyAlgorithm, String keySpec
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
    public Result<K, TextError> acquireKey(CryptoToken cryptoToken, String keyAlgorithm) {
        logger.debug("Acquiring a signing key of CryptoToken '{}' with algorithm '{}'",
                     cryptoToken.identifier(), keyAlgorithm
        );
        // Use ReentrantLock instead of synchronized to allow virtual threads to unmount during blocking I/O
        ReentrantLock lock = cryptoTokenLocks.computeIfAbsent(cryptoToken.id(), id -> new ReentrantLock());
        lock.lock();

        try {
            // Execute database operations inside a transaction, but only after acquiring the lock
            // This ensures threads wait for the lock WITHOUT holding a database connection
            return acquireKeyInTransaction(cryptoToken, keyAlgorithm)
                    .flatMap(key ->
                             key.map(acquiredKey -> {
                                 logger.info("Signing key acquired for CryptoToken '{}' with algorithm '{}'",
                                              cryptoToken.identifier(), keyAlgorithm
                                 );
                                 return Result.<K, TextError>success(acquiredKey);
                             }).orElseGet(() -> {
                                 logger.debug(
                                         "No Signing key found for CryptoToken '{}' with algorithm '{}'. Will generate a new one on the fly.",
                                         cryptoToken.identifier(), keyAlgorithm
                                 );
                                 var genKeyResult = findKeyProfileAndGenerateKeyOnSignserver(cryptoToken, keyAlgorithm)
                                         .mapError(e -> e.extend(
                                                 "Couldn't generate a new signing key for CryptoToken '%s.",
                                                 cryptoToken.identifier()
                                         ));

                                 if (genKeyResult instanceof Error(var err)) {
                                     return Result.error(err.extend(
                                             "'.",
                                             cryptoToken.identifier()
                                     ));
                                 }

                                 String generatedKeyAlias = genKeyResult.unwrap();
                                 return saveAndAcquireKeyInTransaction(cryptoToken, keyAlgorithm, generatedKeyAlias);
                             })
                    );
        } catch (Exception e) {
            logger.error("An exception occurred while acquiring a signing key for CryptoToken '{}' with algorithm '{}'.",
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

    private Result<Optional<K>, TextError> acquireKeyInTransaction(CryptoToken cryptoToken, String keyAlgorithm) {
        return transactionTemplate.execute(status -> {
            try {
                Optional<K> key = keysRepository.findFirstByCryptoTokenIdAndKeyAlgorithmAndInUse(cryptoToken.id(),
                                                                                                 keyAlgorithm,
                                                                                                 false
                                                )
                                                .map(entity -> {
                                                    entity.setAcquiredAt(ZonedDateTime.now());
                                                    entity.setInUse(true);
                                                    E savedEntity = keysRepository.save(entity);
                                                    return this.mapEntityToSigningKey(savedEntity, cryptoToken);
                                                });
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

    private Result<K, TextError> saveAndAcquireKeyInTransaction(CryptoToken cryptoToken, String keyAlgorithm,
                                                                String generatedKeyAlias
    ) {
        try {
            return transactionTemplate.execute(status ->
                   saveKey(cryptoToken, generatedKeyAlias, keyAlgorithm)
                       .flatMap(entity -> {
                           try {
                               entity.setAcquiredAt(ZonedDateTime.now());
                               entity.setInUse(true);
                               E savedEntity = keysRepository.save(entity);

                               logger.debug(
                                       "Acquired a newly generated signing key '{}'",
                                       savedEntity.getId()
                               );
                               return Result.success(savedEntity);
                           } catch (Exception e) {
                               status.setRollbackOnly();
                               logger.error("Couldn't mark the newly generated key as acquired in the database.", e);
                               return Result.error(
                                       TextError.of("Couldn't mark the newly generated key as acquired in the database.")
                               );
                           }
                       })
                       .map(savedEntity -> this.mapEntityToSigningKey(savedEntity, cryptoToken))
                       .mapError(e -> e.extend(
                               "Couldn't acquire newly generate signing key for CryptoToken '%s'.",
                               cryptoToken.identifier()
                       ))
               );
            } catch (Exception e) {
                logger.error("Couldn't save the newly generated key to the database. Going to remove the key '{}' from signserver.", generatedKeyAlias, e);
                signserverClient.removeKey(cryptoToken.id(), generatedKeyAlias)
                                .ifError(() -> logger.warn("Couldn't remove the newly generated key {} from signserver.",generatedKeyAlias,  e))
                                .ifSuccess(() -> logger.info("The newly generated key {} was removed from signserver.", generatedKeyAlias));
                return Result.error(TextError.of("Couldn't save the newly generated key %s to the database.", generatedKeyAlias));
            }

    }

    private Result<String, TextError> findKeyProfileAndGenerateKeyOnSignserver(CryptoToken cryptoToken, String keyAlgorithm) {
        // Select the first KeyPoolProfile that matches the key algorithm and designated usage.
        // If no KeyPoolProfile is found, return Result with an error.
        return cryptoToken.keyPoolProfiles().stream()
                          .filter(kpp -> kpp.keyAlgorithm().equals(keyAlgorithm) && kpp.designatedUsage() == this.getKeyUsageDesignation())
                          .findFirst()
                          .map(kpp -> {
                              String keyAlias = String.format("%s-%s", kpp.keyPrefix(), UUID.randomUUID());
                              return signserverClient.generateKey(cryptoToken, keyAlias, keyAlgorithm, kpp.keySpecification());
                          })
                          .orElseGet(() -> {
                              logger.error("No KeyPoolProfile found for key algorithm '{}' in CryptoToken '{}' and usage '{}'.",
                                           keyAlgorithm, cryptoToken.identifier(), this.getKeyUsageDesignation()
                              );
                              return Result.error(TextError.of(
                                      "No KeyPoolProfile found for key algorithm '%s' in CryptoToken '%s' and usage  '%s'.",
                                      keyAlgorithm, cryptoToken.identifier(), this.getKeyUsageDesignation())
                              );
                          });
    }

    public Result<K, TextError> getKey(UUID keyId) {
        logger.debug("Obtaining signing key with id {}", keyId);
        Optional<E> keyEntity = keysRepository.findById(keyId);

        if (keyEntity.isPresent()) {
            return workerRepository.getCryptoToken(keyEntity.get().getCryptoTokenId())
                                   .map(cryptoToken -> this.mapEntityToSigningKey(keyEntity.get(),
                                                                                  cryptoToken
                                   ))
                                   .mapError(e -> e.extend("Can't retrieve key with id '%s'.", keyId));
        } else {
            return Result.error(TextError.of("Signing key with id '%s' does not exist.", keyId));
        }
    }

    public Result<Void, TextError> deleteKey(UUID keyId) {
        return getKey(keyId).flatMap(this::deleteKey)
                            .mapError(e -> e.extend("Can't delete key with id '%s'.", keyId));
    }

    @Override
    public Result<Void, TextError> deleteKey(K key) {
        logger.debug("Deleting key '{}' with id '{}'", key.keyAlias(), key.id());
        try {
            return signserverClient.removeKeyOkIfNotExists(key.cryptoToken().id(), key.keyAlias())
                                   .flatMap(v -> {
                                       try {
                                           keysRepository.deleteById(key.id());
                                       } catch (Exception e) {
                                           logger.error("Failed to delete signing key '{}' with id '{}' from database.",
                                                        key.keyAlias(), key.id(), e
                                           );
                                           Result.error(TextError.of("Key '%s' not deleted from database.", key.keyAlias()));
                                       }
                                       return Result.emptySuccess();
                                   })
                                   .mapError(e -> e.extend("Key '%s' with id '%s' couldn't be deleted.", key.keyAlias(),
                                                           key.id()
                                   ));
        } catch (Exception e) {
            logger.error("Key '{}' with id '{}' couldn't be deleted.", key.keyAlias(), key.id(), e);
            return Result.error(TextError.of("Key '%s' with id '%s' couldn't be deleted.", key.keyAlias(), key.id()));
        }
    }

    private Result<E, TextError> saveKey(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm) {
        E newEntity = createNewKeyEntity(cryptoToken, keyAlias, keyAlgorithm);
        try {
            logger.debug("Saving new signing key '{}' to the database.", newEntity.getId());
            logger.trace("Signing key: {}", newEntity);
            E savedEntity = keysRepository.save(newEntity);
            logger.info("New signing key '{}' was saved to the database.", savedEntity.getId());
            return Result.success(savedEntity);
        } catch (Exception e) {
            logger.error("Signing key couldn't be saved to the database.", e);
            return Result.error(new TextError("Key couldn't be saved to the database."));
        }
    }

    public abstract K mapEntityToSigningKey(E entity, CryptoToken cryptoToken);

    public abstract E createNewKeyEntity(CryptoToken cryptoToken, String keyAlias, String keyAlgorithm);
}
