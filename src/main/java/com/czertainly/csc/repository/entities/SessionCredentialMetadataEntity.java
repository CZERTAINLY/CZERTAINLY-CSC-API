package com.czertainly.csc.repository.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.StringJoiner;
import java.util.UUID;

@Entity
@Table(name = "session_credentials")
public class SessionCredentialMetadataEntity {

    @Id
    private UUID id;
    private String userId;
    private String keyAlias;
    private UUID keyId;
    private String endEntityName;
    private String signatureQualifier;
    private int multisign;
    private String cryptoTokenName;

    public SessionCredentialMetadataEntity() {
    }

    public SessionCredentialMetadataEntity(
            UUID id, String userId, String keyAlias, UUID keyId, String endEntityName, String signatureQualifier, int multisign,
            String cryptoTokenName
    ) {
        this.id = id;
        this.userId = userId;
        this.keyAlias = keyAlias;
        this.keyId = keyId;
        this.endEntityName = endEntityName;
        this.signatureQualifier = signatureQualifier;
        this.multisign = multisign;
        this.cryptoTokenName = cryptoTokenName;
    }

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

    public UUID getKeyId() {
        return keyId;
    }

    public void setKeyId(UUID keyId) {
        this.keyId = keyId;
    }

    public String getEndEntityName() {
        return endEntityName;
    }

    public void setEndEntityName(String endEntityName) {
        this.endEntityName = endEntityName;
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

    public String getCryptoTokenName() {
        return cryptoTokenName;
    }

    public void setCryptoTokenName(String cryptoTokenName) {
        this.cryptoTokenName = cryptoTokenName;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", SessionCredentialMetadataEntity.class.getSimpleName() + "[", "]")
                .add("id=" + id)
                .add("userId='" + userId + "'")
                .add("keyAlias='" + keyAlias + "'")
                .add("keyId=" + keyId)
                .add("endEntityName='" + endEntityName + "'")
                .add("signatureQualifier='" + signatureQualifier + "'")
                .add("multisign=" + multisign)
                .add("cryptoTokenName='" + cryptoTokenName + "'")
                .toString();
    }
}
