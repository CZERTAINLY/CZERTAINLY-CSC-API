package com.czertainly.signserver.csc.signing.configuration.loader;

import java.util.List;

public class WorkerConfigurationFile {
    List<CryptoTokenDefinition> cryptoTokens;
    List<WorkerConfiguration> signers;

    public List<CryptoTokenDefinition> getCryptoTokens() {
        return cryptoTokens;
    }

    public void setCryptoTokens(List<CryptoTokenDefinition> cryptoTokens
    ) {
        this.cryptoTokens = cryptoTokens;
    }

    public List<WorkerConfiguration> getSigners() {
        return signers;
    }

    public void setSigners(List<WorkerConfiguration> signers
    ) {
        this.signers = signers;
    }
}
