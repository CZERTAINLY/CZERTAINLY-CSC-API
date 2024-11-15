package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

public record SessionToken(SessionCredentialMetadata credentialMetadata) implements SigningToken {

    private static final Logger logger = LoggerFactory.getLogger(SessionToken.class);

    @Override
    public String getKeyAlias() {
        return credentialMetadata.keyAlias();
    }

    @Override
    public Boolean canSignData(List<String> data) {
        boolean canSignEnoughDocuments = credentialMetadata.multisign() >= data.size();
        if (!canSignEnoughDocuments) {
            logger.info("Session Token '{}' belonging to session credential '{}' cannot sign requested {} documents, because it is configured to sign only {} documents at once.",
                        credentialMetadata.keyAlias(), credentialMetadata.session().credentialId(), data.size(), credentialMetadata.multisign());
        }
        return canSignEnoughDocuments;
    }

    public UUID getSessionId() {
        return credentialMetadata.session().id();
    }

}
