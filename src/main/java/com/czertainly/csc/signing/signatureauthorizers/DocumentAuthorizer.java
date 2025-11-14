package com.czertainly.csc.signing.signatureauthorizers;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.AlgorithmHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.NoSuchElementException;

@Component
public class DocumentAuthorizer implements SignatureAuthorizer {

    private static final Logger logger = LoggerFactory.getLogger(DocumentAuthorizer.class);

    private final AlgorithmHelper algorithmHelper;
    private final HashAuthorizer hashAuthorizer;
    private final Base64.Encoder base64Encoder = Base64.getEncoder();
    private final Base64.Decoder base64Decoder = Base64.getDecoder();

    public DocumentAuthorizer(AlgorithmHelper algorithmHelper, HashAuthorizer hashAuthorizer) {
        this.algorithmHelper = algorithmHelper;
        this.hashAuthorizer = hashAuthorizer;
    }

    @Override
    public Result<Boolean, TextError> authorize(List<String> documents, SignatureActivationData sad) {
        try {
            String digestAlgorithmOID = sad.getHashAlgorithmOID().orElseThrow();
            return createMessageDigest(digestAlgorithmOID)
                    .flatMap(messageDigest -> hashDocuments(documents, messageDigest))
                    .flatMap(documentHashes -> hashAuthorizer.authorize(documentHashes, sad));
        } catch (NoSuchElementException e) {
            logger.error("No hash algorithm OID provided in the signature activation data.");
            return Result.error(TextError.of("No hash algorithm OID provided in the signature activation data."));
        }
    }

    private Result<MessageDigest, TextError> createMessageDigest(String digestAlgorithmOID) {
        String digestAlgorithmName = algorithmHelper.getDigestAlgorithmName(digestAlgorithmOID);
        logger.trace("Digest algorithm name for OID '{}' is '{}'", digestAlgorithmOID, digestAlgorithmName);

        if (digestAlgorithmName == null) {
            return Result.error(TextError.of("Unknown digest algorithm OID: " + digestAlgorithmOID));
        }
        try {
            return Result.success(MessageDigest.getInstance(digestAlgorithmName));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Unable to obtain instance of Message Digest '{}'", digestAlgorithmName, e);
            return Result.error(TextError.of("Unable to obtain instance of Message Digest '{}'" + digestAlgorithmOID));
        }
    }

    private Result<List<String>, TextError> hashDocuments(List<String> documents, MessageDigest messageDigest) {
        try {
            List<String> documentHashes = documents
                    .stream()
                    .map(document -> messageDigest.digest(base64Decoder.decode(document)))
                    .map(base64Encoder::encodeToString)
                    .toList();
            return Result.success(documentHashes);
        } catch (Exception e) {
            logger.error("Failed to compute a document hash.", e);
            return Result.error(TextError.of("Failed to compute a document hash."));
        }
    }
}
