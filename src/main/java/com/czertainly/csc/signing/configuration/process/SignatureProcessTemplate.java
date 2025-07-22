package com.czertainly.csc.signing.configuration.process;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.TokenConfiguration;
import com.czertainly.csc.signing.configuration.process.signers.DocumentSigner;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import com.czertainly.csc.signing.configuration.process.token.TokenProvider;
import com.czertainly.csc.signing.signatureauthorizers.SignatureAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class SignatureProcessTemplate<
        TC extends TokenConfiguration,
        C extends SignatureProcessConfiguration,
        T extends SigningToken
        > {

    private static final Logger logger = LoggerFactory.getLogger(SignatureProcessTemplate.class);
    private final SignatureAuthorizer signatureAuthorizer;
    private final WorkerRepository workerRepository;
    private final TokenProvider<TC, C, T> tokenProvider;
    private final DocumentSigner<C> signer;

    public SignatureProcessTemplate(SignatureAuthorizer signatureAuthorizer,
                                       WorkerRepository workerRepository, TokenProvider<TC, C, T> tokenProvider,
                                       DocumentSigner<C> signer
    ) {
        this.signatureAuthorizer = signatureAuthorizer;
        this.workerRepository = workerRepository;
        this.tokenProvider = tokenProvider;
        this.signer = signer;
    }

    public Result<SignedDocuments, TextError> sign(C configuration, TC tokenConfiguration,  List<String> data) {
        var authorizationResult = signatureAuthorizer.authorize(data, configuration.sad());
        if (authorizationResult instanceof Error(var err))
            return Result.error(err.extend("Failed to authorize signature request."));
        Boolean authorized = authorizationResult.unwrap();

        if (authorized) {
            var getWorkerResult = getWorker(configuration);
            if (getWorkerResult instanceof Error(var err))
                return Result.error(err.extend("Failed to obtain suitable worker for the signature request."));
            WorkerWithCapabilities worker = getWorkerResult.unwrap();

            var getSigningTokenResult = tokenProvider.getSigningToken(configuration, tokenConfiguration, worker);
            if (getSigningTokenResult instanceof Error(var err))
                return Result.error(err.extend("Failed to get signing token for the signature request."));
            T signingToken = getSigningTokenResult.unwrap();

            if (!signingToken.canSignData(data, configuration.sad().getNumSignatures())) {
                return Result.error(TextError.of("Selected signing token cannot sign the requested data."));
            }

            // Here we can assume that the signing token is valid and can be used for signing.
            // Therefore, we can clean up the signing token after the signing process independently of the result
            Result<SignedDocuments, TextError> result;
            try {
                result = signer.sign(data, configuration, signingToken, worker)
                        .mapError(err -> err.extend("Error occurred during signing."));
            } finally {
                tokenProvider.cleanup(signingToken);
            }
            return result;
        } else {
            return Result.error(TextError.of("Signature request was not authorized."));
        }
    }

    protected Result<WorkerWithCapabilities, TextError> getWorker(
            SignatureProcessConfiguration configuration
    ) {
        var requiredWorkerCapabilities = CapabilitiesFilter
                .configure()
                .withSignatureQualifier(configuration.signatureQualifier())
                .withSignatureFormat(configuration.signatureFormat())
                .withConformanceLevel(configuration.conformanceLevel())
                .withSignatureAlgorithm(configuration.signatureAlgorithm().toJavaName())
                .withSignaturePackaging(configuration.signaturePackaging())
                .withReturnValidationInfo(configuration.returnValidationInfo())
                .withDocumentType(configuration.documentType())
                .build();

        WorkerWithCapabilities worker = workerRepository.selectWorker(requiredWorkerCapabilities);
        if (worker == null) {
            logger.error("No worker found for the given capabilities: {}.", requiredWorkerCapabilities);
            return Result.error(TextError.of("No worker with matching capabilities found."));
        }
        logger.debug("Selected worker: {}.", worker.worker().workerName());
        return Result.success(worker);
    }

}
