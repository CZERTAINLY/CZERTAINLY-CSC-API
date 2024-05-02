package com.czertainly.signserver.csc.signing.configuration.loader;

public class WorkerConfiguration {
    private String name;
    private int id = -1;
    private String cryptoToken;
    private WorkerCapabilitiesConfiguration capabilities;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getCryptoToken() {
        return cryptoToken;
    }

    public void setCryptoToken(String cryptoToken) {
        this.cryptoToken = cryptoToken;
    }

    public WorkerCapabilitiesConfiguration getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(WorkerCapabilitiesConfiguration capabilities
    ) {
        this.capabilities = capabilities;
    }
}
