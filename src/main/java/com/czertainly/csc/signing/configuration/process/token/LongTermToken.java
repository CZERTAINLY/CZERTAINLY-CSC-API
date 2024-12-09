package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.model.csc.CredentialMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public record LongTermToken(CredentialMetadata credentialMetadata) implements SigningToken {

    private static final Logger logger = LoggerFactory.getLogger(LongTermToken.class);

    @Override
    public String getKeyAlias() {
        return credentialMetadata.keyAlias();
    }

    @Override
    public Boolean canSignData(List<String> data, int numberOfDocumentsAuthorizedBySad) {
        if (credentialMetadata.multisign() < data.size()) {
            logger.warn(
                    "LongTermToken '{}' cannot sign requested '{}' documents, because it is configured to sign only '{}' documents at once.",
                    credentialMetadata.keyAlias(), data.size(), credentialMetadata.multisign());
            return false;
        }

        if (credentialMetadata.multisign() < numberOfDocumentsAuthorizedBySad) {
            logger.warn(
                    "LongTermToken '{}' cannot sign requested '{}' documents, because it is configured to sign only '{}' documents at once but the Signature Activation Data allows to sign '{}' documents.",
                    credentialMetadata.keyAlias(), data.size(), credentialMetadata.multisign(),
                    numberOfDocumentsAuthorizedBySad
            );
            return false;
        }
        return true;
    }
}
