package com.otilm.csc.signing.filter;

import com.otilm.csc.model.signserver.CryptoToken;

public record Worker(String workerName, int workerId, CryptoToken cryptoToken) {
}
