package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentContentSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.List;

public class DocumentContentSigner<C extends DocumentContentSignatureProcessConfiguration> implements DocumentSigner<C> {

    public static final Logger logger = LoggerFactory.getLogger(DocumentContentSigner.class);

    private final SignserverClient signserverClient;

    public DocumentContentSigner(
            SignserverClient signserverClient
    ) {
        this.signserverClient = signserverClient;
    }

    @Override
    public Result<SignedDocuments, TextError> sign(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        Result<SignedDocuments, TextError> result;
        if (data.size() == 1) {
            if (configuration.returnValidationInfo()) {
                result = signSingleContentWithValidationInfo(data, configuration, signingToken, worker);
            } else {
                result = signSingleContent(data, configuration, signingToken, worker);
            }
        } else {
            return Result.error(TextError.of("Document content signing does not support multiple documents."));
        }

        return result.flatMap(signed -> verifyNumberOfSignatures(data, signed));
    }

    private Result<SignedDocuments, TextError> signSingleContent(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signSingleContent(
                worker.worker().workerName(),
                Base64.getDecoder().decode(data.getFirst().getBytes()),
                signingToken.getKeyAlias(),
                configuration.signaturePackaging()
        ).map(SignedDocuments::of);
    }

    private Result<SignedDocuments, TextError> signSingleContentWithValidationInfo(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signSingleContentWithValidationData(
                worker.worker().workerName(),
                Base64.getDecoder().decode(data.getFirst().getBytes()),
                signingToken.getKeyAlias(),
                configuration.signaturePackaging()
        );
    }

    private Result<SignedDocuments, TextError> verifyNumberOfSignatures(List<String> data, SignedDocuments signed) {
        if (signed.signatures().size() != data.size()) {
            logger.error("The number of signatures does not match the number of documents.");
            return Result.error(TextError.of("The number of signatures does not match the number of documents."));
        }
        return Result.success(signed);
    }
}
