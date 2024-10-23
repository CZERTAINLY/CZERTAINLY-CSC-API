package com.czertainly.csc.signing.configuration.profiles.credentialprofile;

import com.czertainly.csc.signing.configuration.profiles.Profile;

import java.time.Duration;
import java.util.StringJoiner;

public class CredentialProfile extends Profile {

    private final String keyAlgorithm;
    private final String keySpecification;
    private final String csrSignatureAlgorithm;

    public CredentialProfile(String name, String certificateAuthority, String certificateProfileName,
                             String endEntityProfileName, Duration certificateValidity,
                             Duration certificateValidityOffset,
                             String keyAlgorithm, String keySpecification, String csrSignatureAlgorithm
    ) {
        super(name, certificateAuthority, certificateProfileName, endEntityProfileName, certificateValidity,
              certificateValidityOffset
        );
        this.keyAlgorithm = keyAlgorithm;
        this.keySpecification = keySpecification;
        this.csrSignatureAlgorithm = csrSignatureAlgorithm;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public String getKeySpecification() {
        return keySpecification;
    }

    public String getCsrSignatureAlgorithm() {
        return csrSignatureAlgorithm;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", CredentialProfile.class.getSimpleName() + "[", "]")
                .add("name='" + getName() + "'")
                .add("certificateAuthority='" + getCertificateAuthority() + "'")
                .add("certificateProfileName='" + getCertificateProfileName() + "'")
                .add("endEntityProfileName='" + getEndEntityProfileName() + "'")
                .add("certificateValidity=" + getCertificateValidity())
                .add("certificateValidityOffset=" + getCertificateValidityOffset())
                .add("keyAlgorithm='" + keyAlgorithm + "'")
                .add("keySpecification='" + keySpecification + "'")
                .add("csrSignatureAlgorithm='" + csrSignatureAlgorithm + "'")
                .toString();
    }
}
