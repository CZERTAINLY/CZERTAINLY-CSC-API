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
    public Boolean canSignData(List<String> data) {
        boolean canSignEnoughDocuments = credentialMetadata.multisign() >= data.size();
        if (!canSignEnoughDocuments) {
            logger.info("LongTermToken {} cannot sign requested {} documents, because it is configured to sign only {} documents at once.",
                    credentialMetadata.keyAlias(), data.size(), credentialMetadata.multisign());
        }
        return canSignEnoughDocuments;
    }
}
