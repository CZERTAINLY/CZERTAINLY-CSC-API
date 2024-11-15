package com.czertainly.csc.signing.configuration.process;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.Signature;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.TokenConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import com.czertainly.csc.signing.configuration.process.token.TokenProvider;
import com.czertainly.csc.signing.signatureauthorizers.SignatureAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class DocumentHashSignatureProcessTemplate<
        TC extends TokenConfiguration,
        C extends DocumentHashSignatureProcessConfiguration,
        T extends SigningToken>
        extends SignatureProcessTemplate<TC, C, T> {

    public static final Logger logger = LoggerFactory.getLogger(DocumentHashSignatureProcessTemplate.class);
    private final SignserverClient signserverClient;

    public DocumentHashSignatureProcessTemplate(
            SignatureAuthorizer signatureAuthorizer,
            WorkerRepository workerRepository,
            TokenProvider<TC, C, T> tokenProvider,
            SignserverClient signserverClient
    ) {
        super(signatureAuthorizer, workerRepository, tokenProvider);
        this.signserverClient = signserverClient;
    }

    @Override
    protected Result<SignedDocuments, TextError> sign(List<String> data, C configuration, T signingToken,
                                                      WorkerWithCapabilities worker
    ) {
        if (data.size() == 1) {
            if (configuration.returnValidationInfo()) {
                return signSingleHashWithValidationInfo(data, configuration, signingToken, worker);
            } else {
                return signSingleHash(data, configuration, signingToken, worker);
            }
        } else {
            if (configuration.returnValidationInfo()) {
                return signMultipleHashesWithValidationInfo(data, configuration, signingToken, worker);
            } else {
                return signMultipleHashes(data, configuration, signingToken, worker);
            }
        }
    }

    private Result<SignedDocuments, TextError> signSingleHash(
            List<String> data, C configuration, T signingToken, WorkerWithCapabilities worker
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
            List<String> data, C configuration, T signingToken, WorkerWithCapabilities worker
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
            List<String> data, C configuration, T signingToken, WorkerWithCapabilities worker
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
            List<String> data, C configuration, T signingToken, WorkerWithCapabilities worker
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
