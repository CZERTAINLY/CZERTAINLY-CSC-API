package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Objects;

public class KeyAndHashSigAlgo implements SignatureAlgorithm {

    private final ASN1ObjectIdentifier keyAlgorithmOid;
    private final ASN1ObjectIdentifier digestAlgorithmOid;
    private final String keyAlgorithmName;
    private final String digestAlgorithmName;

    private KeyAndHashSigAlgo(ASN1ObjectIdentifier keyAlgorithm, ASN1ObjectIdentifier digestAlgorithm, AlgorithmHelper algorithmHelper) {
        this.keyAlgorithmOid = keyAlgorithm;
        this.digestAlgorithmOid = digestAlgorithm;
        this.keyAlgorithmName = algorithmHelper.getAlgorithmName(keyAlgorithm);
        this.digestAlgorithmName = algorithmHelper.getDigestAlgorithmName(digestAlgorithm);
    }

    public static KeyAndHashSigAlgo of(ASN1ObjectIdentifier keyAlgorithm, ASN1ObjectIdentifier digestAlgorithm, AlgorithmHelper algorithmHelper) {
        return new KeyAndHashSigAlgo(keyAlgorithm, digestAlgorithm, algorithmHelper);
    }

    @Override
    public String encryptionAlgorithm() {
        return keyAlgorithmName;
    }

    @Override
    public String digestAlgorithm() {
        return digestAlgorithmName;
    }

    public String toJavaName() {
        return digestAlgorithmName + "With" + keyAlgorithmName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyAndHashSigAlgo that)) return false;
        return Objects.equals(keyAlgorithmOid, that.keyAlgorithmOid) && Objects.equals(digestAlgorithmOid, that.digestAlgorithmOid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyAlgorithmOid, digestAlgorithmOid);
    }

    @Override
    public String toString() {
        return "KeyAndHashSigAlgo[keyAlgorithm=" + keyAlgorithmName + ", digestAlgorithm=" + digestAlgorithmName + "]";
    }
}
