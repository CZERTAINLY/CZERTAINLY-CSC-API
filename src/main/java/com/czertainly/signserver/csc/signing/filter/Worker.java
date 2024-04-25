package com.czertainly.signserver.csc.signing.filter;

import com.czertainly.signserver.csc.model.signserver.CryptoToken;

public record Worker(String workerName, int workerId, CryptoToken cryptoToken) {
}
