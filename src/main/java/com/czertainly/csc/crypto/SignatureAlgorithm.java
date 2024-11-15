package com.czertainly.csc.crypto;

public record SignatureAlgorithm(String keyAlgorithm, String digestAlgorithm) {

    public String toJavaName() {
        return digestAlgorithm + "With" + keyAlgorithm;
    }

}
