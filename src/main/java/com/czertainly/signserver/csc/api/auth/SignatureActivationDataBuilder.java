package com.czertainly.signserver.csc.api.auth;

import java.util.Set;

public class SignatureActivationDataBuilder {

    private String credentialID;
    private String signatureQualifier;
    private int numSignatures;
    private Set<String> hashes;
    private String hashAlgorithmOID;
    private String clientData;

    public SignatureActivationData build() {
        return new SignatureActivationData(credentialID, signatureQualifier, numSignatures, hashes, hashAlgorithmOID, clientData);
    }

    public SignatureActivationDataBuilder withCredentialID(String credentialID) {
        this.credentialID = credentialID;
        return this;
    }

    public SignatureActivationDataBuilder withSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
        return this;
    }

    public SignatureActivationDataBuilder withNumSignatures(int numSignatures) {
        this.numSignatures = numSignatures;
        return this;
    }

    public SignatureActivationDataBuilder withHashes(Set<String> hashes) {
        this.hashes = hashes;
        return this;
    }

    public SignatureActivationDataBuilder withHashAlgorithmOID(String hashAlgorithmOID) {
        this.hashAlgorithmOID = hashAlgorithmOID;
        return this;
    }

    public SignatureActivationDataBuilder withClientData(String clientData) {
        this.clientData = clientData;
        return this;
    }

}
