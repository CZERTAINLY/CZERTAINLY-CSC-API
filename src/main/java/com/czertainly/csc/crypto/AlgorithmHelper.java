package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Resolves and classifies cryptographic algorithm OIDs into signature, key,
 * and digest categories.
 *
 * <p>Uses BouncyCastle finders to map {@link ASN1ObjectIdentifier} values to
 * human-readable algorithm names and to verify compatibility between digest
 * and signature algorithms.
 */
@Component
public class AlgorithmHelper {

    private static final Logger logger = LoggerFactory.getLogger(AlgorithmHelper.class);

    private static final Map<ASN1ObjectIdentifier, AlgorithmFamily> ALGORITHM_REGISTRY = Map.ofEntries(
            // KEY — bare key algorithms requiring a separate digest
            Map.entry(PKCSObjectIdentifiers.rsaEncryption, AlgorithmFamily.RSAES_PKCS1),

            // KEY_AND_HASH — composite signature algorithms
            Map.entry(PKCSObjectIdentifiers.sha256WithRSAEncryption, AlgorithmFamily.RSASSA_PKCS1),
            Map.entry(PKCSObjectIdentifiers.sha384WithRSAEncryption, AlgorithmFamily.RSASSA_PKCS1),
            Map.entry(PKCSObjectIdentifiers.sha512WithRSAEncryption, AlgorithmFamily.RSASSA_PKCS1),
            // ECDSA — composite ECDSA signature algorithms (no standalone key OID)
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA256, AlgorithmFamily.ECDSA),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA384, AlgorithmFamily.ECDSA),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA512, AlgorithmFamily.ECDSA),

            // PSS — RSASSA-PSS requiring a separate digest
            Map.entry(PKCSObjectIdentifiers.id_RSASSA_PSS, AlgorithmFamily.RSASSA_PSS),

            // PURE — algorithms with intrinsic digest (no external hash)
            Map.entry(EdECObjectIdentifiers.id_Ed25519, AlgorithmFamily.EdDSA),
            Map.entry(EdECObjectIdentifiers.id_Ed448, AlgorithmFamily.EdDSA)
    );

    private static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> COMPOSITE_TO_KEY_ALGORITHM = Map.of(
            PKCSObjectIdentifiers.sha256WithRSAEncryption, PKCSObjectIdentifiers.rsaEncryption,
            PKCSObjectIdentifiers.sha384WithRSAEncryption, PKCSObjectIdentifiers.rsaEncryption,
            PKCSObjectIdentifiers.sha512WithRSAEncryption, PKCSObjectIdentifiers.rsaEncryption
    );

    private final DefaultSignatureNameFinder defaultSignatureNameFinder = new DefaultSignatureNameFinder();
    private final CustomAlgorithmNameFinder algorithmNameFinder = new CustomAlgorithmNameFinder();
    private final DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

    /**
     * Returns the {@link AlgorithmFamily} for the given OID, or {@code null} if not in the registry.
     */
    public @Nullable AlgorithmFamily getFamily(@Nullable ASN1ObjectIdentifier identifier) {
        if (identifier == null) {
            return null;
        }
        return ALGORITHM_REGISTRY.get(identifier);
    }

    /**
     * Returns the key algorithm OID for a composite RSA signature algorithm OID.
     *
     * @param compositeOid  the composite signature algorithm OID (e.g. sha256WithRSAEncryption)
     * @return the key algorithm OID (e.g. rsaEncryption), or {@code null} if not found
     */
    public @Nullable ASN1ObjectIdentifier getKeyAlgorithmFromComposite(@NonNull ASN1ObjectIdentifier compositeOid) {
        return COMPOSITE_TO_KEY_ALGORITHM.get(compositeOid);
    }

    /**
     * Returns the human-readable name for any algorithm OID.
     *
     * @param identifier  the algorithm OID, not null
     * @return the algorithm name, or the OID string if not recognized
     */
    public String getAlgorithmName(@NonNull ASN1ObjectIdentifier identifier) {
        return algorithmNameFinder.getAlgorithmName(identifier);
    }

    /**
     * Returns the human-readable name for a signature algorithm OID.
     *
     * @param identifier  the signature algorithm OID, not null
     * @return the algorithm name (for example, "SHA256withRSA")
     */
    public String getSignatureAlgorithmName(@NonNull ASN1ObjectIdentifier identifier) {
        return defaultSignatureNameFinder.getAlgorithmName(identifier);
    }

    /**
     * Returns the human-readable name for a digest algorithm OID.
     *
     * @param identifier  the digest algorithm OID, not null
     * @return the algorithm name (for example, "SHA-256")
     */
    public String getDigestAlgorithmName(@NonNull ASN1ObjectIdentifier identifier) {
        return algorithmNameFinder.getAlgorithmName(identifier);
    }

    /**
     * Returns the human-readable name for a digest algorithm given its OID string.
     *
     * @param oid  the dot-notation OID string (for example, "2.16.840.1.101.3.4.2.1"), not null
     * @return the algorithm name (for example, "SHA-256"), or {@code null} if the OID is malformed
     */
    public String getDigestAlgorithmName(@NonNull String oid) {
        try {
            ASN1ObjectIdentifier identifier = new ASN1ObjectIdentifier(oid);
            return algorithmNameFinder.getAlgorithmName(identifier);
        } catch (IllegalArgumentException e) {
            logger.error("Can not convert OID to ASN1ObjectIdentifier: {}", oid);
            return null;
        }
    }

    /**
     * Resolves a key algorithm name to its corresponding OID.
     *
     * @param algorithmName  the key algorithm name (for example, "RSA"), not null
     * @return the corresponding {@link ASN1ObjectIdentifier}
     */
    public ASN1ObjectIdentifier getKeyAlgorithmIdentifier(@NonNull String algorithmName) {
        return algorithmNameFinder.getKeyAlgorithmIdentifier(algorithmName);
    }

    /**
     * Checks whether the given OID represents a known key algorithm.
     *
     * @param identifier  the algorithm OID to check, not null
     * @return {@code true} if the OID is recognized as a key algorithm
     */
    public boolean isKeyAlgorithm(@NonNull ASN1ObjectIdentifier identifier) {
        boolean isKnown = getFamily(identifier) == AlgorithmFamily.RSAES_PKCS1;
        if (!isKnown) {
            logger.debug("Algorithm OID {} does not represent a known key algorithm.", identifier);
        }
        return isKnown;
    }

    /**
     * Checks whether the given OID represents a known digest algorithm.
     *
     * @param identifier  the algorithm OID to check, not null
     * @return {@code true} if the OID is recognized as a digest algorithm
     */
    public boolean isDigestAlgorithm(@NonNull ASN1ObjectIdentifier identifier) {
        boolean isKnown = defaultDigestAlgorithmIdentifierFinder.find(getHumanReadableName(identifier)) != null;
        if (!isKnown) {
            logger.debug("Algorithm OID {} does not represent a known digest algorithm.", identifier);
        }
        return isKnown;
    }

    /**
     * Extracts the digest algorithm OID from a signature algorithm OID.
     *
     * @param signatureAlgorithm  the signature algorithm OID, not null
     * @return the digest algorithm OID, or {@code null} if the digest cannot be determined
     */
    public ASN1ObjectIdentifier getDigestAlgorithmFromSignatureAlgorithm(@NonNull ASN1ObjectIdentifier signatureAlgorithm) {
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(signatureAlgorithm);
        AlgorithmIdentifier digestAlgId = defaultDigestAlgorithmIdentifierFinder.find(sigAlgId);
        if (digestAlgId == null) {
            return null;
        }
        return digestAlgId.getAlgorithm();
    }

    /**
     * Checks whether a digest algorithm is compatible with a signature algorithm.
     *
     * @param digestAlgorithm     the digest algorithm OID, not null
     * @param signatureAlgorithm  the signature algorithm OID, not null
     * @return {@code true} if the algorithms are compatible
     */
    public boolean isDigestAlgorithmCompatibleWithSignatureAlgorithm(@NonNull ASN1ObjectIdentifier digestAlgorithm,
                                                                     @NonNull ASN1ObjectIdentifier signatureAlgorithm
    ) {
        logger.debug("Checking if digest algorithm {} is compatible with signature algorithm {}", digestAlgorithm,
                     signatureAlgorithm
        );
        if (!isDigestAlgorithm(digestAlgorithm)) {
            logger.debug("The provided OID {} is not recognized as a digest algorithm.", digestAlgorithm);
            return false;
        }

        String signatureAlgorithmName = getSignatureAlgorithmName(signatureAlgorithm);
        logger.trace("Signature algorithm with OID {} was converted to name {}", signatureAlgorithm,
                signatureAlgorithmName
        );
        String digestAlgorithmName = getDigestAlgorithmName(digestAlgorithm);
        logger.trace("Digest algorithm with OID {} was converted to name {}", digestAlgorithm,
                digestAlgorithmName
        );

        return signatureAlgorithmName.contains(digestAlgorithmName);

    }

    private String getHumanReadableName(@NonNull ASN1ObjectIdentifier identifier) {
        return algorithmNameFinder.getAlgorithmName(identifier);
    }
}
