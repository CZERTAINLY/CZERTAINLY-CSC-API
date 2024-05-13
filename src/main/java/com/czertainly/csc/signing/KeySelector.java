package com.czertainly.csc.signing;

import com.czertainly.csc.model.signserver.CryptoTokenKey;

public interface KeySelector {

    CryptoTokenKey selectKey(int workerId);

    void markKeyAsUsed(CryptoTokenKey key);

}
