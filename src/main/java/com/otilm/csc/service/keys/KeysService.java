package com.otilm.csc.service.keys;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.configuration.keypools.KeyUsageDesignation;
import com.otilm.csc.model.signserver.CryptoToken;

public interface KeysService<K extends SigningKey> {

    Result<Integer, TextError> getNumberOfUsableKeys(CryptoToken cryptoToken, String keyAlgorithm);

    Result<K, TextError> generateKey(
            CryptoToken cryptoToken, String keyAlias, String keyAlgorithm, String keySpec
    );

    Result<K, TextError> acquireKey(CryptoToken cryptoToken, String keyAlgorithm);

    Result<Void, TextError> deleteKey(K key);

    KeyUsageDesignation getKeyUsageDesignation();
}
