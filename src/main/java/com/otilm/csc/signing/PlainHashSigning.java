package com.otilm.csc.signing;

import com.otilm.csc.clients.signserver.SignserverClient;
import com.otilm.csc.common.result.Error;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.model.PlainSignature;
import com.otilm.csc.model.SignHashParameters;
import com.otilm.csc.model.SignaturesContainer;
import com.otilm.csc.service.credentials.CredentialsService;
import com.otilm.csc.signing.configuration.WorkerRepository;
import com.otilm.csc.signing.configuration.process.SignatureProcessTemplate;
import com.otilm.csc.signing.configuration.process.configuration.LongTermTokenConfiguration;
import com.otilm.csc.signing.configuration.process.configuration.PlainHashSignatureProcessConfiguration;
import com.otilm.csc.signing.configuration.process.signers.PlainHashSigner;
import com.otilm.csc.signing.configuration.process.token.LongTermToken;
import com.otilm.csc.signing.configuration.process.token.LongTermTokenProvider;
import com.otilm.csc.signing.signatureauthorizers.HashAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class PlainHashSigning {
    private final static Logger logger = LoggerFactory.getLogger(PlainHashSigning.class);

    private final SignatureProcessTemplate<LongTermTokenConfiguration, PlainHashSignatureProcessConfiguration, LongTermToken, PlainSignature> longTermContentSignature;

    SignserverClient signserverClient;
    WorkerRepository workerRepository;


    public PlainHashSigning(WorkerRepository workerRepository, SignserverClient signserverClient,
                            CredentialsService credentialsService
    ) {
        HashAuthorizer documentAuthorizer = new HashAuthorizer();

        LongTermTokenProvider<PlainHashSignatureProcessConfiguration> longTermTokenProvider = new LongTermTokenProvider<>(
                credentialsService
        );

        PlainHashSigner<PlainHashSignatureProcessConfiguration> documentContentSigner = new PlainHashSigner<>(
                signserverClient);

        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;

        longTermContentSignature = new SignatureProcessTemplate<>(
                documentAuthorizer,
                workerRepository,
                longTermTokenProvider,
                documentContentSigner
        );
    }

    public Result<SignaturesContainer<PlainSignature>, TextError> sign(SignHashParameters parameters
    ) {
        if (parameters.hashes().isEmpty()) {
            return Result.error(TextError.of("No hashes to sign."));
        }

        PlainHashSignatureProcessConfiguration configuration = new PlainHashSignatureProcessConfiguration(
                parameters.userID(),
                parameters.sad(),
                parameters.signatureAlgorithm()
        );


        logger.info("Signing with long term token with credential ID: {}", parameters.credentialID());
        LongTermTokenConfiguration tokenConfiguration = new LongTermTokenConfiguration(
                parameters.credentialID()
        );
        Result<SignaturesContainer<PlainSignature>, TextError> signatureResult = longTermContentSignature.sign(
                configuration, tokenConfiguration, parameters.hashes()
        );

        if (signatureResult instanceof Error(var err))
            return Result.error(err.extend("Failed to sign one of the document digest to sign."));
        SignaturesContainer<PlainSignature> docs = signatureResult.unwrap();

        return Result.success(docs);
    }
}
