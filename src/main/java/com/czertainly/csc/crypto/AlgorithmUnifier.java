package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

/**
 * Resolves CSC API algorithm OIDs into a unified {@link SignatureAlgorithm}.
 *
 * <p>The CSC API allows clients to specify algorithms in two ways:
 * <ul>
 *   <li>A <b>signature algorithm OID</b> (e.g. SHA256withRSA) that already combines digest and key algorithm</li>
 *   <li>A <b>key algorithm OID</b> (e.g. RSA) paired with a separate <b>hash algorithm OID</b> (e.g. SHA-256)</li>
 * </ul>
 *
 * <p>This component normalizes both forms into a single {@link SignatureAlgorithm} containing
 * the key algorithm and digest algorithm names, validating compatibility along the way.
 */
@Component
public class AlgorithmUnifier {

    AlgorithmHelper algorithmHelper;

    public AlgorithmUnifier(AlgorithmHelper algorithmHelper) {
        this.algorithmHelper = algorithmHelper;
    }

    /**
     * Unifies the provided algorithm OIDs into a {@link SignatureAlgorithm}.
     *
     * @param signAlgoOID      OID of a signature algorithm (e.g. SHA256withRSA) or a key algorithm (e.g. RSA)
     * @param hashAlgorithmOID OID of the hash/digest algorithm, or {@code null} if {@code signAlgoOID}
     *                         already encodes the digest. If both {@code signAlgoOID} encodes a digest
     *                         and this parameter is provided, they are checked for compatibility
     * @return a {@link SignatureAlgorithm} on success, or an {@link AlgorithmUnificationError} describing the failure
     */
    public Result<SignatureAlgorithm, AlgorithmUnificationError> unify(@NonNull String signAlgoOID,
                                                                  @Nullable String hashAlgorithmOID
    ) {
        try {
            ASN1ObjectIdentifier signAlgo = toObjectIdentifier(signAlgoOID);
            ASN1ObjectIdentifier digestAlgo = hashAlgorithmOID != null ? toObjectIdentifier(hashAlgorithmOID) : null;

            AlgorithmFamily family = algorithmHelper.getFamily(signAlgo);
            if (family == null) {
                return Result.error(new AlgorithmUnificationError.UnsupportedAlgorithm());
            }

            return switch (family) {
                case RSAES_PKCS1 -> resolveFromRsaEncryptionAlgorithm(signAlgo, digestAlgo);
                case RSASSA_PKCS1 -> resolveFromRsaSignatureAlgorithm(signAlgo, digestAlgo);
                case ECDSA -> resolveFromEcdsaSignatureAlgorithm(signAlgo, digestAlgo);
                case RSASSA_PSS -> resolveFromRsaSsaPssAlgorithm(digestAlgo);
                case EdDSA -> resolvePureAlgorithm(signAlgo, digestAlgo);
            };
        } catch (IllegalArgumentException e) {
            return Result.error(new AlgorithmUnificationError.OtherError(e.getMessage()));
        }
    }

    private Result<SignatureAlgorithm, AlgorithmUnificationError> resolveFromRsaEncryptionAlgorithm(
            @NonNull ASN1ObjectIdentifier keyAlgo,
            @Nullable ASN1ObjectIdentifier digestAlgo
    ) {
        if (digestAlgo == null) {
            return Result.error(new AlgorithmUnificationError.DigestAlgorithmMissing());
        }
        return Result.success(KeyAndHashSigAlgo.of(keyAlgo, digestAlgo, algorithmHelper));
    }

    private Result<SignatureAlgorithm, AlgorithmUnificationError> resolveFromRsaSignatureAlgorithm(
            @NonNull ASN1ObjectIdentifier signAlgo,
            @Nullable ASN1ObjectIdentifier digestAlgo
    ) {
        ASN1ObjectIdentifier keyAlgo = algorithmHelper.getKeyAlgorithmFromComposite(signAlgo);
        if (keyAlgo == null) {
            return Result.error(new AlgorithmUnificationError.OtherError(
                    "Cannot determine key algorithm from composite signature algorithm OID %s.".formatted(signAlgo.getId())));
        }

        if (digestAlgo != null) {
            if (!algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(digestAlgo, signAlgo)) {
                return Result.error(new AlgorithmUnificationError.IncompatibleAlgorithms());
            }
            return Result.success(KeyAndHashSigAlgo.of(keyAlgo, digestAlgo, algorithmHelper));
        }

        ASN1ObjectIdentifier extractedDigest = algorithmHelper.getDigestAlgorithmFromSignatureAlgorithm(signAlgo);
        if (extractedDigest == null) {
            return Result.error(new AlgorithmUnificationError.OtherError(
                    "Cannot determine digest algorithm from signature algorithm OID %s.".formatted(signAlgo.getId())));
        }
        return Result.success(KeyAndHashSigAlgo.of(keyAlgo, extractedDigest, algorithmHelper));
    }

    private Result<SignatureAlgorithm, AlgorithmUnificationError> resolveFromEcdsaSignatureAlgorithm(
            @NonNull ASN1ObjectIdentifier signAlgo,
            @Nullable ASN1ObjectIdentifier digestAlgo
    ) {
        if (digestAlgo != null) {
            if (!algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(digestAlgo, signAlgo)) {
                return Result.error(new AlgorithmUnificationError.IncompatibleAlgorithms());
            }
            return Result.success(EcdsaSigAlgo.of(signAlgo, digestAlgo, algorithmHelper));
        }

        ASN1ObjectIdentifier extractedDigest = algorithmHelper.getDigestAlgorithmFromSignatureAlgorithm(signAlgo);
        if (extractedDigest == null) {
            return Result.error(new AlgorithmUnificationError.OtherError(
                    "Cannot determine digest algorithm from signature algorithm OID %s.".formatted(signAlgo.getId())));
        }
        return Result.success(EcdsaSigAlgo.of(signAlgo, extractedDigest, algorithmHelper));
    }

    private Result<SignatureAlgorithm, AlgorithmUnificationError> resolveFromRsaSsaPssAlgorithm(
            @Nullable ASN1ObjectIdentifier digestAlgo
    ) {
        if (digestAlgo == null) {
            return Result.error(new AlgorithmUnificationError.DigestAlgorithmMissing());
        }
        return Result.success(PssSignatureAlgo.of(digestAlgo, algorithmHelper));
    }

    private Result<SignatureAlgorithm, AlgorithmUnificationError> resolvePureAlgorithm(
            @NonNull ASN1ObjectIdentifier signAlgo,
            @Nullable ASN1ObjectIdentifier digestAlgo
    ) {
        if (digestAlgo != null) {
            return Result.error(new AlgorithmUnificationError.DigestAlgorithmNotAllowed());
        }
        return Result.success(PureSignatureAlgo.of(signAlgo, algorithmHelper));
    }

    private ASN1ObjectIdentifier toObjectIdentifier(String oid) {
        ASN1ObjectIdentifier identifier = ASN1ObjectIdentifier.tryFromID(oid);
        if (identifier == null) {
            throw new IllegalArgumentException("The provided OID %s is not known.".formatted(oid));
        }
        return identifier;
    }
}
