package com.czertainly.csc.signing;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoTokenKey;

public interface KeySelector {

    Result<CryptoTokenKey, TextError> selectKey(int workerId);

    Result<Void, TextError> markKeyAsUsed(CryptoTokenKey key);

}
