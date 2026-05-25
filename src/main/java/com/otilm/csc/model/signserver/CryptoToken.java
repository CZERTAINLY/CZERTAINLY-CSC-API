package com.otilm.csc.model.signserver;

import com.otilm.csc.configuration.keypools.KeyPoolProfile;

import java.util.List;

public record CryptoToken(String name, int id, List<KeyPoolProfile> keyPoolProfiles) {

    public String identifier() {
        return String.format("%s (%d)", name, id);
    }
}
