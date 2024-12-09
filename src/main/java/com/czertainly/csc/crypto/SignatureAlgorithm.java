package com.czertainly.csc.crypto;

public record SignatureAlgorithm(String keyAlgorithm, String digestAlgorithm) {

    public static SignatureAlgorithm of(String keyAlgorithm, String digestAlgorithm) {
        return new SignatureAlgorithm(keyAlgorithm, digestAlgorithm);
    }

    public static SignatureAlgorithm fromJavaName(String javaName) {
        String[] parts = javaName.split("With");
        return new SignatureAlgorithm(parts[1], parts[0]);
    }

    public String toJavaName() {
        return digestAlgorithm + "With" + keyAlgorithm;
    }

}
