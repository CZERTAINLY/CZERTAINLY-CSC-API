package com.czertainly.csc.model.signserver;

import com.czertainly.csc.configuration.keypools.KeyPoolProfile;

import java.util.List;

public record CryptoToken(String name, int id, List<KeyPoolProfile> keyPoolProfiles) {

    public String identifier() {
        return String.format("%s (%d)", name, id);
    }
}
