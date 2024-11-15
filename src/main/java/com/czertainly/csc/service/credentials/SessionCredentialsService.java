package com.czertainly.csc.service.credentials;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.model.csc.SignatureQualifierBasedCredentialMetadata;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.repository.SessionCredentialsRepository;
import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class SessionCredentialsService {

    private static final Logger logger = LoggerFactory.getLogger(SessionCredentialsService.class);
    private final SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory;
    private final SessionCredentialsRepository sessionCredentialsRepository;


    public SessionCredentialsService(SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory,
                                     SessionCredentialsRepository sessionCreRequestFactory
    ) {
        this.signatureQualifierBasedCredentialFactory = signatureQualifierBasedCredentialFactory;
        this.sessionCredentialsRepository = sessionCreRequestFactory;
    }

    public Result<SessionCredentialMetadata, TextError> createCredential(
            CredentialSession session, CryptoTokenKey key, String signatureQualifier, String userId, SignatureActivationData sad,
            CscAuthenticationToken cscAuthenticationToken
    ) {
        return signatureQualifierBasedCredentialFactory.createCredential(key, signatureQualifier, userId, sad,
                                                                         cscAuthenticationToken
                                                       )
                                                       .flatMap(credentialMetadata -> saveCredentialToDatabase(
                                                               session.credentialId(), credentialMetadata)
                                                       )
                                                       .map(credentialMetadata -> new SessionCredentialMetadata(
                                                               session,
                                                               credentialMetadata.key().keyAlias(),
                                                               credentialMetadata.endEntityName(),
                                                               credentialMetadata.multisign()
                                                       ));
    }

    private Result<SignatureQualifierBasedCredentialMetadata, TextError> saveCredentialToDatabase(UUID credentialId,
                                                                                                  SignatureQualifierBasedCredentialMetadata credentialMetadata
    ) {
        try {
            SessionCredentialMetadataEntity credentialMetadataEntity = new SessionCredentialMetadataEntity(
                    credentialId, credentialMetadata.userId(), credentialMetadata.key().keyAlias(),
                    credentialMetadata.endEntityName(), credentialMetadata.signatureQualifier(),
                    credentialMetadata.multisign(),
                    credentialMetadata.key().cryptoToken().name()
            );
            sessionCredentialsRepository.save(credentialMetadataEntity);
            return Result.success(credentialMetadata);
        } catch (Exception e) {
            logger.error("Failed to save session credential '{}' to database", credentialId, e);
            return Result.error(new TextError("Failed to save session credential to database."));
        }
    }
}
