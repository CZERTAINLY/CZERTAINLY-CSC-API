package com.czertainly.csc.signing.configuration.loader;

import java.util.List;

public class CryptoTokenDefinition {

    private String name;
    private int id = -1;
    private List<String> keyPoolProfiles;

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

    public List<String> getKeyPoolProfiles() {
        return keyPoolProfiles;
    }

    public void setKeyPoolProfiles(List<String> keyPoolProfiles) {
        this.keyPoolProfiles = keyPoolProfiles;
    }
}