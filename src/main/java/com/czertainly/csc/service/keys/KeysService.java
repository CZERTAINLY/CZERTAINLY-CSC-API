package com.czertainly.csc.service.keys;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface KeysService<K extends SigningKey> {

    Result<Integer, TextError> getNumberOfUsableKeys(CryptoToken cryptoToken, String keyAlgorithm);

    Result<K, TextError> generateKey(
            CryptoToken cryptoToken, String keyAlias, String keyAlgorithm, String keySpec
    );

    @Transactional
    Result<K, TextError> acquireKey(CryptoToken cryptoToken, String keyAlgorithm);

    Result<K, TextError> getKey(UUID keyId);

    Result<Void, TextError> deleteKey(K key);
}
