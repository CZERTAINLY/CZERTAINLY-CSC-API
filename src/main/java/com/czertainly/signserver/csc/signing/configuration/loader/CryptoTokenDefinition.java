package com.czertainly.signserver.csc.signing.configuration.loader;

public class CryptoTokenDefinition {

    String name;
    int id = -1;

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

}