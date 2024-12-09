package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.service.credentials.SigningSession;
import com.czertainly.csc.service.credentials.CredentialSessionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

public record SessionToken(SessionCredentialMetadata credentialMetadata, SigningSession session) implements SigningToken {

    private static final Logger logger = LoggerFactory.getLogger(SessionToken.class);

    @Override
    public String getKeyAlias() {
        return credentialMetadata.keyAlias();
    }

    @Override
    public Boolean canSignData(List<String> data, int numberOfDocumentsAuthorizedBySad) {
        if (session.status() != CredentialSessionStatus.ACTIVE) {
            logger.warn("Session Token '{}' belonging to session credential '{}' cannot be used to sign documents as the session is not active. The session status is '{}'.",
                        credentialMetadata.keyAlias(), session().credentialId(), session.status());
            return false;
        }

        boolean canSignEnoughDocuments = credentialMetadata.multisign() >= data.size();
        if (!canSignEnoughDocuments) {
            logger.warn("Session Token '{}' belonging to session credential '{}' cannot sign requested {} documents, because it is configured to sign only {} documents at once.",
                        credentialMetadata.keyAlias(), session().credentialId(), data.size(), credentialMetadata.multisign());
            return false;
        }

        if (numberOfDocumentsAuthorizedBySad > credentialMetadata.multisign()) {
            logger.warn("Session Token '{}' belonging to session credential '{}' cannot sign requested {} documents, because it is configured to sign only {} documents at once but the Signature Activation Data allows to sign {} documents.",
                        credentialMetadata.keyAlias(), session().credentialId(), data.size(), credentialMetadata.multisign(), numberOfDocumentsAuthorizedBySad);
            return false;
        }

        return true;
    }

    public UUID getSessionId() {
        return session().id();
    }
}
