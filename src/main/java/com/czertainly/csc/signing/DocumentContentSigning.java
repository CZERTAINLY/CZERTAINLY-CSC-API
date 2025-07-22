package com.czertainly.csc.signing;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.AlgorithmHelper;
import com.czertainly.csc.model.DocumentContentToSign;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.service.credentials.CredentialsService;
import com.czertainly.csc.service.credentials.SessionCredentialsService;
import com.czertainly.csc.service.credentials.SignatureQualifierBasedCredentialFactory;
import com.czertainly.csc.service.credentials.SigningSessionsService;
import com.czertainly.csc.service.keys.OneTimeKeyAsyncDeletionService;
import com.czertainly.csc.service.keys.OneTimeKeysService;
import com.czertainly.csc.service.keys.SessionKeysService;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.process.SignatureProcessTemplate;
import com.czertainly.csc.signing.configuration.process.configuration.*;
import com.czertainly.csc.signing.configuration.process.signers.DocumentContentSigner;
import com.czertainly.csc.signing.configuration.process.token.*;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import com.czertainly.csc.signing.signatureauthorizers.DocumentAuthorizer;
import com.czertainly.csc.signing.signatureauthorizers.DocumentHashAuthorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DocumentContentSigning {

    private final static Logger logger = LoggerFactory.getLogger(DocumentContentSigning.class);

    private final SignatureProcessTemplate<LongTermTokenConfiguration, DocumentContentSignatureProcessConfiguration, LongTermToken> longTermContentSignature;
    private final SignatureProcessTemplate<OneTimeTokenConfiguration, DocumentContentSignatureProcessConfiguration, OneTimeToken> oneTimeContentSignature;
    private final SignatureProcessTemplate<SessionTokenConfiguration, DocumentContentSignatureProcessConfiguration, SessionToken> sessionContentSignature;

    private final SignatureTypeDecider signatureTypeDecider;

    SignserverClient signserverClient;
    WorkerRepository workerRepository;


    public DocumentContentSigning(WorkerRepository workerRepository,
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
        DocumentAuthorizer documentAuthorizer = new DocumentAuthorizer(
                new AlgorithmHelper(), new DocumentHashAuthorizer()
        );

        LongTermTokenProvider<DocumentContentSignatureProcessConfiguration> longTermTokenProvider = new LongTermTokenProvider<>(
                credentialsService
        );
        OneTimeTokenProvider<DocumentContentSignatureProcessConfiguration> oneTimeTokenProvider = new OneTimeTokenProvider<>(
                signatureQualifierBasedCredentialFactory,
                oneTimeKeySelector,
                oneTimeKeysService,
                asyncDeletionService
        );
        SessionTokenProvider<DocumentContentSignatureProcessConfiguration> sessionTokenProvider = new SessionTokenProvider<>(
                signingSessionsService,
                sessionCredentialsService,
                credentialProfileRepository,
                sessionKeySelector,
                sessionKeysService
        );

        DocumentContentSigner<DocumentContentSignatureProcessConfiguration> documentContentSigner = new DocumentContentSigner<>(
                signserverClient);

        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;

        longTermContentSignature = new SignatureProcessTemplate<>(
                documentAuthorizer,
                workerRepository,
                longTermTokenProvider,
                documentContentSigner
        );
        oneTimeContentSignature = new SignatureProcessTemplate<>(
                documentAuthorizer,
                workerRepository,
                oneTimeTokenProvider,
                documentContentSigner
        );
        sessionContentSignature = new SignatureProcessTemplate<>(
                documentAuthorizer,
                workerRepository,
                sessionTokenProvider,
                documentContentSigner
        );
    }

    public Result<SignedDocuments, TextError> sign(SignDocParameters parameters, CscAuthenticationToken cscAuthenticationToken) {
        if (parameters.documentsToSign().isEmpty()) {
            return Result.error(TextError.of("No documents to sign."));
        }

        SignedDocuments signedDocuments = SignedDocuments.empty();
        for (DocumentContentToSign documentToSign : parameters.documentsToSign()) {
            DocumentContentSignatureProcessConfiguration configuration = new DocumentContentSignatureProcessConfiguration(
                    parameters.userID(),
                    parameters.sad(),
                    parameters.signatureQualifier(),
                    documentToSign.signatureFormat(),
                    documentToSign.conformanceLevel(),
                    documentToSign.signaturePackaging(),
                    documentToSign.signatureAlgorithm(),
                    parameters.returnValidationInfo()
            );

            Result<SignedDocuments, TextError> signatureResult = null;
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
                    signatureResult = longTermContentSignature.sign(configuration, tokenConfiguration,
                            List.of(documentToSign.content())
                    );
                }
                case ONE_TIME -> {
                    logger.info("Signing with one time token.");
                    OneTimeTokenConfiguration tokenConfiguration = new OneTimeTokenConfiguration(
                            cscAuthenticationToken
                    );
                    signatureResult = oneTimeContentSignature.sign(configuration, tokenConfiguration,
                            List.of(documentToSign.content())
                    );
                }
                case SESSION -> {
                    logger.info("Signing with session token. Session ID: {}", parameters.sessionId().orElseThrow());
                    SessionTokenConfiguration tokenConfiguration = new SessionTokenConfiguration(
                            parameters.sessionId().orElseThrow(), cscAuthenticationToken
                    );
                    signatureResult = sessionContentSignature.sign(configuration, tokenConfiguration,
                            List.of(documentToSign.content()));
                }
            }

            if (signatureResult instanceof Error(var err))
                return Result.error(err.extend("Failed to sign one of the document digest to sign."));
            SignedDocuments docs = signatureResult.unwrap();
            signedDocuments.extend(docs);
        }

        return Result.success(signedDocuments);
    }

}
