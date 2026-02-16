package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Objects;

/**
 * A {@link SignatureAlgorithm} for RSASSA-PSS, which requires a separate
 * digest algorithm OID. It is assumed that the mask function is always MGF1.
 */
public class PssSignatureAlgo implements SignatureAlgorithm {

    private static final String KEY_ALGORITHM_NAME = "RSASSA-PSS";

    private final ASN1ObjectIdentifier digestAlgorithmOid;
    private final String digestAlgorithmName;

    private PssSignatureAlgo(ASN1ObjectIdentifier digestAlgorithmOid, AlgorithmHelper algorithmHelper) {
        this.digestAlgorithmOid = digestAlgorithmOid;
        this.digestAlgorithmName = algorithmHelper.getDigestAlgorithmName(digestAlgorithmOid);
    }

    public static PssSignatureAlgo of(ASN1ObjectIdentifier digestAlgo, AlgorithmHelper helper) {
        return new PssSignatureAlgo(digestAlgo, helper);
    }

    @Override
    public String encryptionAlgorithm() {
        return KEY_ALGORITHM_NAME;
    }

    @Override
    public String digestAlgorithm() {
        return digestAlgorithmName;
    }

    @Override
    public String toJavaName() {
        String javaDigestName = DigestAlgorithmJavaName.get(digestAlgorithmName);
        return javaDigestName.replace("-", "") + "withRSAandMGF1";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PssSignatureAlgo that)) return false;
        return Objects.equals(digestAlgorithmOid, that.digestAlgorithmOid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(digestAlgorithmOid);
    }

    @Override
    public String toString() {
        return "PssSignatureAlgo[digest=" + digestAlgorithmName + "]";
    }
}
