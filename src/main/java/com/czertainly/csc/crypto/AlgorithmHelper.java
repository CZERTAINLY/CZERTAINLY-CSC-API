package com.czertainly.csc.crypto;

import com.czertainly.csc.providers.KeyValueSource;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AlgorithmHelper {

    private static final Logger logger = LoggerFactory.getLogger(AlgorithmHelper.class);
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
            logger.debug("Algorithm OID {} is not a valid OID and hence not valid signature algorithm.", algorithmOID);
            return false;
        }

        boolean isKnown =  defaultSignatureNameFinder.hasAlgorithmName(identifier);
        if (!isKnown) {
            logger.debug("Algorithm OID {} does not represent a known signature algorithm.", algorithmOID);
        }
        return isKnown;
    }

    public boolean isKeyAlgorithm(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            logger.debug("Algorithm OID {} is not a valid OID and hence not valid key algorithm.", algorithmOID);
            return false;
        }
        String algorithmName = defaultAlgorithmNameFinder.getAlgorithmName(identifier);
        boolean isKnown = keyAlgorithms.contains(algorithmName);
        if (!isKnown) {
            logger.debug("Algorithm OID {} does not represent a known key algorithm.", algorithmOID);
        }
        return isKnown;
    }

    public boolean isDigestAlgorithm(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            logger.debug("Algorithm OID {} is not a valid OID and hence not valid digest algorithm.", algorithmOID);
            return false;
        }
        boolean isKnown = defaultDigestAlgorithmIdentifierFinder.find(getHumanReadableName(identifier)) != null;
        if (!isKnown) {
            logger.debug("Algorithm OID {} does not represent a known digest algorithm.", algorithmOID);
        }
        return isKnown;
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
            logger.debug("Algorithm OID {} is not a valid OID and hence not valid digest algorithm.", algorithmOID);
            return null;
        }
        return defaultAlgorithmNameFinder.getAlgorithmName(identifier);
    }

    public String getAlgorithmName(String algorithmOID) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(algorithmOID);
        if (identifier == null) {
            logger.debug("Algorithm OID {} is not a valid OID and hence not valid algorithm.", algorithmOID);
            return null;
        }
        return defaultAlgorithmNameFinder.getAlgorithmName(identifier);
    }

    public boolean isDigestAlgorithmCompatibleWithSignatureAlgorithm(String digestAlgorithmOID,
                                                                     String signatureAlgorithmOID
    ) {
        logger.debug("Checking if digest algorithm {} is compatible with signature algorithm {}", digestAlgorithmOID,
                     signatureAlgorithmOID
        );
        if (!isSignatureAlgorithm(signatureAlgorithmOID)) {
            return false;
        }
        if (!isDigestAlgorithm(digestAlgorithmOID)) {
            return false;
        }
        String signatureAlgorithmName = getSignatureAlgorithmName(signatureAlgorithmOID);
        logger.debug("Signature algorithm with IOD {} was converted to name {}", signatureAlgorithmOID,
                     signatureAlgorithmName
        );
        String digestAlgorithmName = getDigestAlgorithmName(digestAlgorithmOID);
        logger.debug("Digest algorithm with IOD {} was converted to name {}", digestAlgorithmOID,
                     digestAlgorithmName
        );

        return signatureAlgorithmName.contains(digestAlgorithmName);
    }

    private String getHumanReadableName(ASN1ObjectIdentifier identifier) {
        return defaultAlgorithmNameFinder.getAlgorithmName(identifier);
    }
}
