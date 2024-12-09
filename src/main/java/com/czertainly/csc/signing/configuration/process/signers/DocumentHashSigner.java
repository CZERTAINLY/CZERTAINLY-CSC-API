package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.Signature;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class DocumentHashSigner<C extends DocumentHashSignatureProcessConfiguration> implements DocumentSigner<C> {

    public static final Logger logger = LoggerFactory.getLogger(DocumentHashSigner.class);

    private final SignserverClient signserverClient;

    public DocumentHashSigner(
            SignserverClient signserverClient
    ) {
        this.signserverClient = signserverClient;
    }

    @Override
    public Result<SignedDocuments, TextError> sign(List<String> data, C configuration, SigningToken signingToken,
                                                   WorkerWithCapabilities worker
    ) {
        Result<SignedDocuments, TextError> result;
        if (data.size() == 1) {
            if (configuration.returnValidationInfo()) {
                result = signSingleHashWithValidationInfo(data, configuration, signingToken, worker);
            } else {
                result = signSingleHash(data, configuration, signingToken, worker);
            }
        } else {
            if (configuration.returnValidationInfo()) {
                result = signMultipleHashesWithValidationInfo(data, configuration, signingToken, worker);
            } else {
                result = signMultipleHashes(data, configuration, signingToken, worker);
            }
        }

        return result.flatMap(signed -> verifyNumberOfSignatures(data, signed));
    }

    private Result<SignedDocuments, TextError> verifyNumberOfSignatures(List<String> data, SignedDocuments signed) {
        if (signed.signatures().size() != data.size()) {
            logger.error("The number of signatures does not match the number of documents.");
            return Result.error(TextError.of("The number of signatures does not match the number of documents."));
        }
        return Result.success(signed);
    }

    private Result<SignedDocuments, TextError> signSingleHash(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        try {
            Signature signature = signserverClient.signSingleHash(
                    worker.worker().workerName(),
                    data.getFirst().getBytes(),
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
            );
            return Result.success(SignedDocuments.of(signature));
        } catch (Exception e) {
            logger.error("The signing of the single document has failed.", e);
            return Result.error(TextError.of("The signing of the single document has failed."));
        }
    }

    private Result<SignedDocuments, TextError> signSingleHashWithValidationInfo(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        try {
            SignedDocuments signedDocuments = signserverClient.signSingleHashWithValidationData(
                    worker.worker().workerName(),
                    data.getFirst().getBytes(),
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
            );
            return Result.success(signedDocuments);
        } catch (Exception e) {
            logger.error("The signing of the documents with validation info has failed.", e);
            return Result.error(TextError.of("The signing of the documents with validation info has failed."));
        }
    }

    private Result<SignedDocuments, TextError> signMultipleHashesWithValidationInfo(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        try {
            SignedDocuments signedDocuments = signserverClient.signMultipleHashesWithValidationData(
                    worker.worker().workerName(),
                    data,
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
            );
            return Result.success(signedDocuments);
        } catch (Exception e) {
            logger.error("The signing of the documents with validation info has failed.", e);
            return Result.error(TextError.of("The signing of the documents with validation info has failed."));
        }
    }

    private Result<SignedDocuments, TextError> signMultipleHashes(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        try {
            List<Signature> signatures = signserverClient.signMultipleHashes(
                    worker.worker().workerName(),
                    data,
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
            );
            return Result.success(SignedDocuments.of(signatures));
        } catch (Exception e) {
            logger.error("The signing of the documents has failed.", e);
            return Result.error(TextError.of("The signing of the documents has failed."));
        }
    }
}
