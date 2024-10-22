package com.czertainly.csc.signing.configuration.profiles.credentialprofile;


public class CredentialProfileConfiguration {

    private String name;
    private String caName;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateValidity;
    private String certificateValidityOffset;
    private String keyAlgorithm;
    private String keySpecification;
    private String csrSignatureAlgorithm;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public String getCertificateValidity() {
        return certificateValidity;
    }

    public void setCertificateValidity(String certificateValidity) {
        this.certificateValidity = certificateValidity;
    }

    public String getCertificateValidityOffset() {
        return certificateValidityOffset;
    }

    public void setCertificateValidityOffset(String certificateValidityOffset) {
        this.certificateValidityOffset = certificateValidityOffset;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getKeySpecification() {
        return keySpecification;
    }

    public void setKeySpecification(String keySpecification) {
        this.keySpecification = keySpecification;
    }

    public String getCsrSignatureAlgorithm() {
        return csrSignatureAlgorithm;
    }

    public void setCsrSignatureAlgorithm(String csrSignatureAlgorithm) {
        this.csrSignatureAlgorithm = csrSignatureAlgorithm;
    }
}
