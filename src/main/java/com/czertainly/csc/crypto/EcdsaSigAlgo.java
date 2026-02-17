package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Objects;

/**
 * A {@link SignatureAlgorithm} for ECDSA composite algorithms (e.g. SHA256withECDSA).
 *
 * <p>Unlike RSA composites, ECDSA has no standalone key OID — the key algorithm
 * is always "ECDSA" and is derived from the composite signature algorithm name.
 */
public class EcdsaSigAlgo implements SignatureAlgorithm {

    private static final String KEY_ALGORITHM_NAME = "ECDSA";

    private final ASN1ObjectIdentifier signatureAlgorithmOid;
    private final ASN1ObjectIdentifier digestAlgorithmOid;
    private final String digestAlgorithmName;

    private EcdsaSigAlgo(ASN1ObjectIdentifier signatureAlgorithmOid, ASN1ObjectIdentifier digestAlgorithmOid, AlgorithmHelper algorithmHelper) {
        this.signatureAlgorithmOid = signatureAlgorithmOid;
        this.digestAlgorithmOid = digestAlgorithmOid;
        this.digestAlgorithmName = algorithmHelper.getDigestAlgorithmName(digestAlgorithmOid);
    }

    public static EcdsaSigAlgo of(ASN1ObjectIdentifier signatureAlgorithmOid, ASN1ObjectIdentifier digestAlgorithmOid, AlgorithmHelper algorithmHelper) {
        return new EcdsaSigAlgo(signatureAlgorithmOid, digestAlgorithmOid, algorithmHelper);
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
        return javaDigestName.replace("-", "") + "WithECDSA";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EcdsaSigAlgo that)) return false;
        return Objects.equals(signatureAlgorithmOid, that.signatureAlgorithmOid) && Objects.equals(digestAlgorithmOid, that.digestAlgorithmOid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signatureAlgorithmOid, digestAlgorithmOid);
    }

    @Override
    public String toString() {
        return "EcdsaSigAlgo[digest=" + digestAlgorithmName + "]";
    }
}
