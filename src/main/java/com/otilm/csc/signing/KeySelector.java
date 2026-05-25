package com.otilm.csc.signing;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.service.keys.SigningKey;

public interface KeySelector<K extends SigningKey> {

    Result<K, TextError> selectKey(int workerId, String keyAlgorithm);

    Result<Void, TextError> markKeyAsUsed(K key);

}
