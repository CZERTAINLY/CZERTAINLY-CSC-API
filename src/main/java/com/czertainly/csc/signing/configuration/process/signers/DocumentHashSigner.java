package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.DocumentSignature;
import com.czertainly.csc.model.SignaturesContainer;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class DocumentHashSigner<C extends DocumentHashSignatureProcessConfiguration> implements Signer<C, DocumentSignature> {

    public static final Logger logger = LoggerFactory.getLogger(DocumentHashSigner.class);

    private final SignserverClient signserverClient;

    public DocumentHashSigner(
            SignserverClient signserverClient
    ) {
        this.signserverClient = signserverClient;
    }

    @Override
    public Result<SignaturesContainer<DocumentSignature>, TextError> sign(List<String> data, C configuration, SigningToken signingToken,
                                                                          WorkerWithCapabilities worker
    ) {
        Result<SignaturesContainer<DocumentSignature>, TextError> result;
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

    private Result<SignaturesContainer<DocumentSignature>, TextError> verifyNumberOfSignatures(List<String> data, SignaturesContainer<DocumentSignature> signed) {
        if (signed.signatures().size() != data.size()) {
            logger.error("The number of signatures does not match the number of documents.");
            return Result.error(TextError.of("The number of signatures does not match the number of documents."));
        }
        return Result.success(signed);
    }

    private Result<SignaturesContainer<DocumentSignature>, TextError> signSingleHash(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signSingleDocumentHash(
                    worker.worker().workerName(),
                    data.getFirst().getBytes(),
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
        );
    }

    private Result<SignaturesContainer<DocumentSignature>, TextError> signSingleHashWithValidationInfo(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signSingleDocumentHashWithValidationData(
                    worker.worker().workerName(),
                    data.getFirst().getBytes(),
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
            );
    }

    private Result<SignaturesContainer<DocumentSignature>, TextError> signMultipleHashesWithValidationInfo(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signMultipleDocumentHashesWithValidationData(
                    worker.worker().workerName(),
                    data,
                    signingToken.getKeyAlias(),
                    configuration.digestAlgorithm()
            );
    }

    private Result<SignaturesContainer<DocumentSignature>, TextError> signMultipleHashes(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signMultipleDocumentHashes(
                worker.worker().workerName(),
                data,
                signingToken.getKeyAlias(),
                configuration.digestAlgorithm()
        );
    }
}
