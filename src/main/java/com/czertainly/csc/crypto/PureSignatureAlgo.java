package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Objects;

/**
 * A {@link SignatureAlgorithm} for pure/intrinsic algorithms that do not use
 * an external digest (e.g. Ed25519, Ed448).
 */
public class PureSignatureAlgo implements SignatureAlgorithm {

    private final ASN1ObjectIdentifier algorithmOid;
    private final String algorithmName;

    private PureSignatureAlgo(ASN1ObjectIdentifier algorithmOid, AlgorithmHelper algorithmHelper) {
        this.algorithmOid = algorithmOid;
        this.algorithmName = algorithmHelper.getSignatureAlgorithmName(algorithmOid);
    }

    public static PureSignatureAlgo of(ASN1ObjectIdentifier signAlgo, AlgorithmHelper helper) {
        return new PureSignatureAlgo(signAlgo, helper);
    }

    @Override
    public String encryptionAlgorithm() {
        return algorithmName;
    }

    @Override
    public String digestAlgorithm() {
        return null;
    }

    @Override
    public String toJavaName() {
        return algorithmName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PureSignatureAlgo that)) return false;
        return Objects.equals(algorithmOid, that.algorithmOid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithmOid);
    }

    @Override
    public String toString() {
        return "PureSignatureAlgo[algorithm=" + algorithmName + "]";
    }
}
