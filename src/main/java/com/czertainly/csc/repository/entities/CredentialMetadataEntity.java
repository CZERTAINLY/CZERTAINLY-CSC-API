package com.czertainly.csc.repository.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.StringJoiner;
import java.util.UUID;

@Entity
@Table(name = "credentials")
public class CredentialMetadataEntity {

    @Id
    private UUID id;
    private String userId;
    private String keyAlias;

    private String endEntityName;
    private String currentCertificateSn;
    private String currentCertificateIssuer;
    private String signatureQualifier;
    private int multisign;
    private String scal;
    private String cryptoTokenName;
    private String description;
    private boolean disabled;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyId) {
        this.keyAlias = keyId;
    }

    public String getEndEntityName() {
        return endEntityName;
    }

    public void setEndEntityName(String endEntityName) {
        this.endEntityName = endEntityName;
    }

    public String getCurrentCertificateSn() {
        return currentCertificateSn;
    }

    public void setCurrentCertificateSn(String currentCertificateSN) {
        this.currentCertificateSn = currentCertificateSN;
    }

    public String getCurrentCertificateIssuer() {
        return currentCertificateIssuer;
    }

    public void setCurrentCertificateIssuer(String currentCertificateIssuerDN) {
        this.currentCertificateIssuer = currentCertificateIssuerDN;
    }

    public String getSignatureQualifier() {
        return signatureQualifier;
    }

    public void setSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    public int getMultisign() {
        return multisign;
    }

    public void setMultisign(int multisign) {
        this.multisign = multisign;
    }

    public String getScal() {
        return scal;
    }

    public void setScal(String scal) {
        this.scal = scal;
    }

    public String getCryptoTokenName() {
        return cryptoTokenName;
    }

    public void setCryptoTokenName(String cryptoTokenName) {
        this.cryptoTokenName = cryptoTokenName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", CredentialMetadataEntity.class.getSimpleName() + "[", "]")
                .add("id=" + id)
                .add("userId='" + userId + "'")
                .add("keyAlias='" + keyAlias + "'")
                .add("endEntityName='" + endEntityName + "'")
                .add("currentCertificateSn='" + currentCertificateSn + "'")
                .add("currentCertificateIssuer='" + currentCertificateIssuer + "'")
                .add("signatureQualifier='" + signatureQualifier + "'")
                .add("multisign=" + multisign)
                .add("scal='" + scal + "'")
                .add("cryptoTokenName='" + cryptoTokenName + "'")
                .add("description='" + description + "'")
                .add("disabled=" + disabled)
                .toString();
    }
}
