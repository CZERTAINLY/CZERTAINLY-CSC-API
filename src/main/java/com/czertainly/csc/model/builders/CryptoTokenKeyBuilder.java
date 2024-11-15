package com.czertainly.csc.model.builders;

import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.model.signserver.CryptoTokenKeyStatus;

import java.util.List;

public class CryptoTokenKeyBuilder {

    private CryptoToken cryptoToken;
    private String keyAlias;
    private String keyAlgorithm;
    private String keySpecification;
    private CryptoTokenKeyStatus status;
    private List<byte[]> chain;

    public CryptoTokenKeyBuilder withCryptoTokenId(CryptoToken cryptoToken) {
        this.cryptoToken = cryptoToken;
        return this;
    }

    public CryptoTokenKeyBuilder withKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
        return this;
    }

    public CryptoTokenKeyBuilder withKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }

    public CryptoTokenKeyBuilder withKeySpecification(String keySpecification) {
        this.keySpecification = keySpecification;
        return this;
    }

    public CryptoTokenKeyBuilder withStatus(CryptoTokenKeyStatus status) {
        this.status = status;
        return this;
    }

    public CryptoTokenKeyBuilder withChain(List<byte[]> chain) {
        this.chain = chain;
        return this;
    }

    public CryptoTokenKey build() {
        return new CryptoTokenKey(cryptoToken, keyAlias, keyAlgorithm, keySpecification,
                                  chain == null ? List.of() : chain, status
        );
    }

}
