package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.service.keys.OneTimeKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public record OneTimeToken(OneTimeKey key, int multisign) implements SigningToken {

    private static final Logger logger = LoggerFactory.getLogger(OneTimeToken.class);

    @Override
    public String getKeyAlias() {
        return key.keyAlias();
    }

    @Override
    public Boolean canSignData(List<String> data) {
        boolean canSignEnoughDocuments = multisign >= data.size();
        if (!canSignEnoughDocuments) {
            logger.info("OneTimeToken {} cannot sign requested {} documents, because it is configured to sign only {} documents at once.",
                        key.keyAlias(), data.size(), multisign);
        }
        return canSignEnoughDocuments;
    }

}
