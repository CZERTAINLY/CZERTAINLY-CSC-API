package com.czertainly.csc.signing;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.service.keys.SigningKey;

public interface KeySelector<K extends SigningKey> {

    Result<K, TextError> selectKey(int workerId, String keyAlgorithm);

    Result<Void, TextError> markKeyAsUsed(K key);

}
