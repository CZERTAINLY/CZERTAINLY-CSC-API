package com.czertainly.signserver.csc.api.auth;

import java.util.Optional;
import java.util.Set;

public class SignatureActivationData {

    private final String credentialID;
    private final String signatureQualifier;
    private final int numSignatures;
    private final Set<String> hashes;
    private final String hashAlgorithmOID;
    private final String clientData;

    public SignatureActivationData(String credentialID, String signatureQualifier, int numSignatures,
                                   Set<String> hashes, String hashAlgorithmOID, String clientData
    ) {
        this.credentialID = credentialID;
        this.signatureQualifier = signatureQualifier;
        this.numSignatures = numSignatures;
        this.hashes = hashes;
        this.hashAlgorithmOID = hashAlgorithmOID;
        this.clientData = clientData;
    }

    public Optional<String> getCredentialID() {
        return Optional.ofNullable(credentialID);
    }

    public Optional<String> getSignatureQualifier() {
        return Optional.ofNullable(signatureQualifier);
    }

    public int getNumSignatures() {
        return numSignatures;
    }

    public Optional<Set<String>> getHashes() {
        return Optional.ofNullable(hashes);
    }

    public Optional<String> getHashAlgorithmOID() {
        return Optional.ofNullable(hashAlgorithmOID);
    }

    public Optional<String> getClientData() {
        return Optional.ofNullable(clientData);
    }
}
