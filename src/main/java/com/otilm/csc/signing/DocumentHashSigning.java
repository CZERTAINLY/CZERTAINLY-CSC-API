package com.otilm.csc.signing;

import com.otilm.csc.api.auth.CscAuthenticationToken;
import com.otilm.csc.clients.signserver.SignserverClient;
import com.otilm.csc.common.result.Error;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.model.DocumentDigestsToSign;
import com.otilm.csc.model.DocumentSignature;
import com.otilm.csc.model.SignDocParameters;
import com.otilm.csc.model.SignaturesContainer;
import com.otilm.csc.service.credentials.CredentialsService;
import com.otilm.csc.service.credentials.SessionCredentialsService;
import com.otilm.csc.service.credentials.SignatureQualifierBasedCredentialFactory;
import com.otilm.csc.service.credentials.SigningSessionsService;
import com.otilm.csc.service.keys.OneTimeKeyAsyncDeletionService;
import com.otilm.csc.service.keys.OneTimeKeysService;
import com.otilm.csc.service.keys.SessionKeysService;
import com.otilm.csc.signing.configuration.WorkerRepository;
import com.otilm.csc.signing.configuration.process.SignatureProcessTemplate;
import com.otilm.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
import com.otilm.csc.signing.configuration.process.configuration.LongTermTokenConfiguration;
import com.otilm.csc.signing.configuration.process.configuration.OneTimeTokenConfiguration;
import com.otilm.csc.signing.configuration.process.configuration.SessionTokenConfiguration;
import com.otilm.csc.signing.configuration.process.signers.DocumentHashSigner;
import com.otilm.csc.signing.configuration.process.token.*;
import com.otilm.csc.signing.configuration.profiles.CredentialProfileRepository;
import com.otilm.csc.signing.signatureauthorizers.HashAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class DocumentHashSigning {

    private final static Logger logger = LoggerFactory.getLogger(DocumentHashSigning.class);

    private final SignatureProcessTemplate<OneTimeTokenConfiguration, DocumentHashSignatureProcessConfiguration, OneTimeToken, DocumentSignature> oneTimeHashSignature;
    private final SignatureProcessTemplate<LongTermTokenConfiguration, DocumentHashSignatureProcessConfiguration, LongTermToken, DocumentSignature> longTermHashSignature;
    private final SignatureProcessTemplate<SessionTokenConfiguration, DocumentHashSignatureProcessConfiguration, SessionToken, DocumentSignature> sessionSignature;
    private final SignatureTypeDecider signatureTypeDecider;

    public DocumentHashSigning(WorkerRepository workerRepository,
                               OneTimeKeySelector oneTimeKeySelector, SessionKeySelector sessionKeySelector,
                               OneTimeKeysService oneTimeKeysService, SessionKeysService sessionKeysService,
                               OneTimeKeyAsyncDeletionService asyncDeletionService,
                               SignserverClient signserverClient, CredentialsService credentialsService,
                               SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory,
                               SigningSessionsService signingSessionsService,
                               SessionCredentialsService sessionCredentialsService,
                               CredentialProfileRepository credentialProfileRepository,
                               SignatureTypeDecider signatureTypeDecider
    ) {
        this.signatureTypeDecider = signatureTypeDecider;
        HashAuthorizer hashAuthorizer = new HashAuthorizer();
        OneTimeTokenProvider<DocumentHashSignatureProcessConfiguration> oneTimeTokenProvider = new OneTimeTokenProvider<>(
                signatureQualifierBasedCredentialFactory, oneTimeKeySelector, oneTimeKeysService, asyncDeletionService);
        LongTermTokenProvider<DocumentHashSignatureProcessConfiguration> longTermTokenProvider = new LongTermTokenProvider<>(
                credentialsService);

        SessionTokenProvider<DocumentHashSignatureProcessConfiguration> sessionTokenProvider = new SessionTokenProvider<>(
                signingSessionsService,
                sessionCredentialsService,
                credentialProfileRepository,
                sessionKeySelector,
                sessionKeysService
        );

        DocumentHashSigner<DocumentHashSignatureProcessConfiguration> documentHashSigner = new DocumentHashSigner<>(
                signserverClient);

        oneTimeHashSignature = new SignatureProcessTemplate<>(
                hashAuthorizer,
                workerRepository,
                oneTimeTokenProvider,
                documentHashSigner
        );

        longTermHashSignature = new SignatureProcessTemplate<>(
                hashAuthorizer,
                workerRepository,
                longTermTokenProvider,
                documentHashSigner
        );

        sessionSignature = new SignatureProcessTemplate<>(
                hashAuthorizer,
                workerRepository,
                sessionTokenProvider,
                documentHashSigner
        );
    }

    public Result<SignaturesContainer<DocumentSignature>, TextError> sign(
            SignDocParameters parameters, CscAuthenticationToken cscAuthenticationToken
    ) {

        if (parameters.documentDigestsToSign().isEmpty()) {
            return Result.error(TextError.of("No document digests to sign."));
        }
        SignaturesContainer<DocumentSignature> signatures = null;
        for (DocumentDigestsToSign digestsToSign : parameters.documentDigestsToSign()) {
            DocumentHashSignatureProcessConfiguration configuration = new DocumentHashSignatureProcessConfiguration(
                    parameters.userID(),
                    parameters.sad(),
                    parameters.signatureQualifier(),
                    digestsToSign.signatureFormat(),
                    digestsToSign.conformanceLevel(),
                    digestsToSign.signaturePackaging(),
                    digestsToSign.signatureAlgorithm(),
                    parameters.returnValidationInfo()
            );

            Result<SignaturesContainer<DocumentSignature>, TextError> signatureResult = null;
            Result<SignatureType, TextError> getSignatureType = signatureTypeDecider.decideType(parameters);
            if (getSignatureType instanceof Error(var err))
                return Result.error(err.extend("Failed to determine signature type."));
            SignatureType signatureType = getSignatureType.unwrap();

            switch (signatureType) {
                case LONG_TERM -> {
                    logger.info("Signing with long term token with credential ID: {}", parameters.credentialID());
                    LongTermTokenConfiguration tokenConfiguration = new LongTermTokenConfiguration(
                            parameters.credentialID()
                    );
                    signatureResult = longTermHashSignature.sign(configuration, tokenConfiguration,
                                                                 digestsToSign.hashes()
                    );
                }
                case ONE_TIME -> {
                    logger.info("Signing with one time token.");
                    OneTimeTokenConfiguration tokenConfiguration = new OneTimeTokenConfiguration(
                            cscAuthenticationToken
                    );
                    signatureResult = oneTimeHashSignature.sign(configuration, tokenConfiguration,
                                                                digestsToSign.hashes()
                    );
                }
                case SESSION -> {
                    logger.info("Signing with session token. Session ID: {}", parameters.sessionId().orElseThrow());
                    SessionTokenConfiguration tokenConfiguration = new SessionTokenConfiguration(
                            parameters.sessionId().orElseThrow(), cscAuthenticationToken
                    );
                    signatureResult = sessionSignature.sign(configuration, tokenConfiguration, digestsToSign.hashes());
                }
            }

            if (signatureResult instanceof Error(var err))
                return Result.error(err.extend("Failed to sign one of the document digest to sign."));
            SignaturesContainer<DocumentSignature> docs = signatureResult.unwrap();
            if (signatures != null) {
                signatures.extend(docs);
            } else {
                signatures = docs;
            }
        }
        return Result.success(signatures);
    }
}
