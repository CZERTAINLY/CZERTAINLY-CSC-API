package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

public class SignatureQualifierProfileConfiguration {

    private String name;
    private String caName;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateValidity;
    private String certificateValidityOffset;
    private String csrSignatureAlgorithm;
    private String usernamePattern;
    private NamePattern dn;
    private NamePattern san;
    private int multisign;

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

    public String getCsrSignatureAlgorithm() {
        return csrSignatureAlgorithm;
    }

    public void setCsrSignatureAlgorithm(String csrSignatureAlgorithm) {
        this.csrSignatureAlgorithm = csrSignatureAlgorithm;
    }

    public String getUsernamePattern() {
        return usernamePattern;
    }

    public void setUsernamePattern(String usernamePattern) {
        this.usernamePattern = usernamePattern;
    }

    public NamePattern getDn() {
        return dn;
    }

    public void setDn(NamePattern dn) {
        this.dn = dn;
    }

    public NamePattern getSan() {
        return san;
    }

    public void setSan(NamePattern san) {
        this.san = san;
    }

    public int getMultisign() {
        return multisign;
    }

    public void setMultisign(int multisign) {
        this.multisign = multisign;
    }
}
