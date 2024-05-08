package com.czertainly.signserver.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AlgorithmHelper {

    private final List<String> keyAlgorithms = List.of("RSA", "ECDSA");

    DefaultSignatureNameFinder defaultSignatureNameFinder = new DefaultSignatureNameFinder();
    DefaultAlgorithmNameFinder defaultAlgorithmNameFinder = new DefaultAlgorithmNameFinder();
    DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

    /*
     * Returns true if the algorithmOID is a signature algorithm.
     * Signature algorithm is a composite of a digest algorithm and a key algorithm.
     */
    public boolean isSignatureAlgorithm(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            return false;
        }
        return defaultSignatureNameFinder.hasAlgorithmName(identifier);
    }

    public boolean isKeyAlgorithm(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            return false;
        }
        String algorithmName = defaultAlgorithmNameFinder.getAlgorithmName(identifier);
        return keyAlgorithms.contains(algorithmName);
    }

    public boolean isDigestAlgorithm(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            return false;
        }
        return defaultDigestAlgorithmIdentifierFinder.find(getHumanReadableName(identifier)) != null;
    }

    public String getSignatureAlgorithmName(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            return null;
        }
        return defaultSignatureNameFinder.getAlgorithmName(identifier);
    }

    public String getDigestAlgorithmName(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            return null;
        }
        return defaultAlgorithmNameFinder.getAlgorithmName(identifier);
    }

    public String getAlgorithmName(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            return null;
        }
        return defaultAlgorithmNameFinder.getAlgorithmName(identifier);
    }

    public boolean isDigestAlgorithmCompatibleWithSignatureAlgorithm(String digestAlgorithmOID,
                                                                     String signatureAlgorithmOID
    ) {
        if (!isSignatureAlgorithm(signatureAlgorithmOID)) {
            return false;
        }
        if (!isDigestAlgorithm(digestAlgorithmOID)) {
            return false;
        }
        String signatureAlgorithmName = getSignatureAlgorithmName(signatureAlgorithmOID);
        String digestAlgorithmName = getDigestAlgorithmName(digestAlgorithmOID);

        return signatureAlgorithmName.contains(digestAlgorithmName);
    }

    private String getHumanReadableName(ASN1ObjectIdentifier identifier) {
        return defaultAlgorithmNameFinder.getAlgorithmName(identifier);
    }
}
