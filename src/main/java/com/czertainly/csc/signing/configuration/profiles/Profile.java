package com.czertainly.csc.signing.configuration.profiles;

import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfile;

import java.time.Duration;
import java.util.StringJoiner;

public class Profile {
    private final String name;
    private final String certificateAuthority;
    private final String certificateProfileName;
    private final String endEntityProfileName;
    private final Duration certificateValidity;
    private final Duration certificateValidityOffset;
    private final String csrSignatureAlgorithm;

    public Profile(String name, String certificateAuthority, String certificateProfileName, String endEntityProfileName,
                   Duration certificateValidity, Duration certificateValidityOffset, String csrSignatureAlgorithm
    ) {
        this.name = name;
        this.certificateAuthority = certificateAuthority;
        this.certificateProfileName = certificateProfileName;
        this.endEntityProfileName = endEntityProfileName;
        this.certificateValidity = certificateValidity;
        this.certificateValidityOffset = certificateValidityOffset;
        this.csrSignatureAlgorithm = csrSignatureAlgorithm;
    }

    public String getName() {
        return name;
    }

    public String getCertificateAuthority() {
        return certificateAuthority;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public Duration getCertificateValidity() {
        return certificateValidity;
    }

    public Duration getCertificateValidityOffset() {
        return certificateValidityOffset;
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
                .toString();
    }
}
