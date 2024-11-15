package com.czertainly.csc.model.signserver;

import java.util.List;

public record CryptoTokenKey(
        CryptoToken cryptoToken,
        String keyAlias,
        String keyAlgorithm,
        String keySpecification,
        List<byte[]> chain,
        CryptoTokenKeyStatus status) {
}
