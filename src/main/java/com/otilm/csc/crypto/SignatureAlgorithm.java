package com.otilm.csc.crypto;

public interface SignatureAlgorithm {

    String encryptionAlgorithm();

    String digestAlgorithm();

    String toJavaName();
}
