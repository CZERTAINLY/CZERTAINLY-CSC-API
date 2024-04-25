package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.model.signserver.CryptoTokenKey;

public interface KeySelector {

    CryptoTokenKey selectKey(int workerId);

}
