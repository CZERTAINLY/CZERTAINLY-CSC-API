package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

public class SignatureQualifierProfileConfiguration {

    private String name;
    private String caName;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateValidity;
    private String certificateValidityOffset;
    private String usernamePattern;
    private NamePattern dn;
    private NamePattern san;

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
}
