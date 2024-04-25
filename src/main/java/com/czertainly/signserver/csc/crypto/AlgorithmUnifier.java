package com.czertainly.signserver.csc.crypto;

import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
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
    public Result<AlgorithmPair, ErrorWithDescription> unify(@NonNull String signAlgo, @Nullable String hashAlgorithmOID) {
        try {
            if (algorithmHelper.isSignatureAlgorithm(signAlgo)) {
                return extractAlgoPairFromSignatureAlgorithm(signAlgo, hashAlgorithmOID);
            } else if (algorithmHelper.isKeyAlgorithm(signAlgo)) {
                return extractAlgoPairFromKeyAndDigestAlgorithm(signAlgo, hashAlgorithmOID);
            } else {
                return Result.error(
                        new ErrorWithDescription("invalid_request",
                                         "Missing (or invalid type) string parameter signAlgo."
                        ));
            }
        } catch (IllegalArgumentException e) {
            return Result.error(
                    new ErrorWithDescription("invalid_request", e.getMessage()));
        }
    }

    private Result<AlgorithmPair, ErrorWithDescription> extractAlgoPairFromKeyAndDigestAlgorithm(
            String signAlgo,
            String hashAlgorithmOID
    ) {
        String digestAlgorithm = algorithmHelper.getDigestAlgorithmName(hashAlgorithmOID);
        if (digestAlgorithm == null) {
            return Result.error(
                    new ErrorWithDescription("invalid_request",
                                     "Missing (or invalid type) string parameter hashAlgorithmOID."
                    ));
        }

        String keyAlgorithm = algorithmHelper.getAlgorithmName(signAlgo);
        if (keyAlgorithm == null) {
            return Result.error(
                    new ErrorWithDescription("invalid_request", "Invalid parameter signAlgo."));
        }
        AlgorithmPair algorithmPair = new AlgorithmPair(keyAlgorithm, digestAlgorithm);
        return Result.ok(algorithmPair);
    }

    private Result<AlgorithmPair, ErrorWithDescription> extractAlgoPairFromSignatureAlgorithm(
            String signAlgo,
            String hashAlgorithmOID
    ) {
        if (hashAlgorithmOID == null) {
            AlgorithmPair algorithmPair = splitSignatureAlgo(signAlgo);
            return Result.ok(algorithmPair);
        } else {
            if (algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(hashAlgorithmOID, signAlgo)) {
                AlgorithmPair algorithmPair = splitSignatureAlgo(signAlgo);
                return Result.ok(algorithmPair);
            } else {
                return Result.error(
                        new ErrorWithDescription("invalid_request",
                                         "The hashAlgorithmOID parameter is not compatible with the signAlgo parameter."
                        ));
            }
        }
    }

    private AlgorithmPair splitSignatureAlgo(String signAlgo) {
        String signatureAlgo = algorithmHelper.getSignatureAlgorithmName(signAlgo);
        String[] parts = signatureAlgo.split(CONJUNCTION);
        if (parts.length != 2) {
            throw new IllegalArgumentException(
                    "Signature algorithm can't be split into two parts delimited by the " + CONJUNCTION + " keyword.");
        }
        return new AlgorithmPair(parts[0], parts[1]);
    }

}
