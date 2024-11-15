package com.czertainly.csc.signing.signatureauthorizers;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DocumentHashAuthorizer implements SignatureAuthorizer {

    private static final Logger logger = LoggerFactory.getLogger(DocumentHashAuthorizer.class);

    @Override
    public Result<Boolean, TextError> authorize(List<String> documentHashes, SignatureActivationData sad) {
        if (sad.getHashes().isEmpty() || !sad.getHashes().get().containsAll(documentHashes)) {
            logger.info("Some document hashes were not authorized by the SAD.");
            logger.debug("Authorized document hashes: {}", sad.getHashes().get());
            logger.debug("Document hashes to Sign: {}", documentHashes);
            return Result.success(false);
        }

        if (sad.getNumSignatures() < documentHashes.size()) {
            logger.info("Number of document hashes to sign is greater than the number of signatures allowed by the SAD.");
            logger.debug("Number of document hashes to sign: {}, Allowed number of signatures by SAD {}", documentHashes.size(), sad.getNumSignatures());
            return Result.success(false);
        }

        logger.debug("The hashes signatures were authorized by the SAD.");
        return Result.success(true);
    }
}
