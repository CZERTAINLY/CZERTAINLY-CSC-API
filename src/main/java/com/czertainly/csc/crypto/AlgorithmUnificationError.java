package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.TextError;

public sealed class AlgorithmUnificationError extends TextError {

    public AlgorithmUnificationError(String error) {
        super(error);
    }

    public static final class SignatureAlgorithmMissing extends AlgorithmUnificationError {
        public SignatureAlgorithmMissing() {
            super("Missing (or invalid type) string parameter signAlgo.");
        }
    }

    public static final class DigestAlgorithmMissing extends AlgorithmUnificationError {
        public DigestAlgorithmMissing() {
            super("Missing (or invalid type) string parameter hashAlgorithmOID.");
        }
    }

    public static final class IncompatibleAlgorithms extends AlgorithmUnificationError {
        public IncompatibleAlgorithms() {
            super("The hashAlgorithmOID parameter is not compatible with the signAlgo parameter.");
        }
    }

    public static final class UnsupportedAlgorithm extends AlgorithmUnificationError {
        public UnsupportedAlgorithm() {
            super("The signAlgo parameter is not a supported algorithm OID.");
        }
    }

    public static final class DigestAlgorithmNotAllowed extends AlgorithmUnificationError {
        public DigestAlgorithmNotAllowed() {
            super("The hashAlgorithmOID parameter must not be provided for this sigAlgo.");
        }
    }

    public static final class OtherError extends AlgorithmUnificationError {
        public OtherError(String error) {
            super(error);
        }
    }
}