package com.czertainly.csc.utils.signing.process;

import com.czertainly.csc.signing.configuration.process.token.SigningToken;

import java.util.List;

public class TestSigningToken implements SigningToken {

    private String keyAlias;
    private Boolean canSignData;

    public static TestSigningToken any() {
        return new TestSigningToken("a-key-alias", true);
    }

    public static TestSigningToken of(String keyAlias, Boolean canSignData) {
        return new TestSigningToken(keyAlias, canSignData);
    }

    public TestSigningToken(String keyAlias, Boolean canSignData) {
        this.keyAlias = keyAlias;
        this.canSignData = canSignData;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public void setCanSignData(Boolean canSignData) {
        this.canSignData = canSignData;
    }

    @Override
    public String getKeyAlias() {
        return keyAlias;
    }

    @Override
    public Boolean canSignData(List<String> data, int numberOfDocumentsAuthorizedBySad) {
        return canSignData;
    }
}
