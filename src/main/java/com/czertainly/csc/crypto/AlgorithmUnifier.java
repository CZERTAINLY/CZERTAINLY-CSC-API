package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

@Component
public class AlgorithmUnifier {

    public static final String CONJUNCTION = "WITH";

    AlgorithmHelper algorithmHelper;

    public AlgorithmUnifier(AlgorithmHelper algorithmHelper) {
        this.algorithmHelper = algorithmHelper;
    }

    /*
     * Unify the signAlgo and hashAlgorithmOID into a pair of a digest algorithm and a key algorithm.
     *
     * @param signAlgo The signature algorithm as received through CSC API. May contain a key algorithm
     *  or a combination of a key algorithm and a digest algorithm. Must not be empty.
     * @param hashAlgorithmOID The hash algorithm OID as received through CSC API. May contain a digest algorithm
     *  or be empty.
     *
     * return A pair of a digest algorithm and a key algorithm.
     */
    public Result<AlgorithmPair, AlgorithmUnificationError> unify(@NonNull String signAlgo,
                                                                  @Nullable String hashAlgorithmOID
    ) {
        try {
            if (algorithmHelper.isSignatureAlgorithm(signAlgo)) {
                return extractAlgoPairFromSignatureAlgorithm(signAlgo, hashAlgorithmOID);
            } else if (algorithmHelper.isKeyAlgorithm(signAlgo)) {
                return extractAlgoPairFromKeyAndDigestAlgorithm(signAlgo, hashAlgorithmOID);
            } else {
                return Result.error(new AlgorithmUnificationError.SignatureAlgorithmMissing());
            }
        } catch (IllegalArgumentException e) {
            return Result.error(new AlgorithmUnificationError.OtherError(e.getMessage()));
        }
    }

    private Result<AlgorithmPair, AlgorithmUnificationError> extractAlgoPairFromKeyAndDigestAlgorithm(
            String signAlgo,
            String hashAlgorithmOID
    ) {
        String digestAlgorithm = algorithmHelper.getDigestAlgorithmName(hashAlgorithmOID);
        if (digestAlgorithm == null) {
            return Result.error(new AlgorithmUnificationError.DigestAlgorithmMissing());
        }

        String keyAlgorithm = algorithmHelper.getAlgorithmName(signAlgo);
        if (keyAlgorithm == null) {
            return Result.error(new AlgorithmUnificationError.SignatureAlgorithmMissing());
        }
        AlgorithmPair algorithmPair = new AlgorithmPair(keyAlgorithm, digestAlgorithm);
        return Result.success(algorithmPair);
    }

    private Result<AlgorithmPair, AlgorithmUnificationError> extractAlgoPairFromSignatureAlgorithm(
            String signAlgo,
            String hashAlgorithmOID
    ) {
        if (hashAlgorithmOID == null) {
            return splitSignatureAlgo(signAlgo);
        } else {
            if (algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(hashAlgorithmOID, signAlgo)) {
                return splitSignatureAlgo(signAlgo);
            } else {
                return Result.error(new AlgorithmUnificationError.IncompatibleAlgorithms());
            }
        }
    }

    private Result<AlgorithmPair, AlgorithmUnificationError> splitSignatureAlgo(String signAlgo) {
        String signatureAlgo = algorithmHelper.getSignatureAlgorithmName(signAlgo);
        String[] parts = signatureAlgo.split(CONJUNCTION);
        if (parts.length != 2) {
            return Result.error(new AlgorithmUnificationError.OtherError(
                    "Signature algorithm can't be split into two parts delimited by the " + CONJUNCTION + " keyword."));
        }
        return Result.success(new AlgorithmPair(parts[1], parts[0]));
    }


}
