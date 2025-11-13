package com.czertainly.csc.service.credentials;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.model.csc.SignatureQualifierBasedCredentialMetadata;
import com.czertainly.csc.repository.SessionCredentialsRepository;
import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import com.czertainly.csc.service.keys.SessionKey;
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

    public Result<SessionCredentialMetadata, TextError> getSessionCredential(SigningSession session) {
        try {
            return sessionCredentialsRepository.findById(session.credentialId())
                                               .map(credentialMetadataEntity -> new SessionCredentialMetadata(
                                                       credentialMetadataEntity.getId(),
                                                       credentialMetadataEntity.getKeyAlias(),
                                                       credentialMetadataEntity.getKeyId(),
                                                       credentialMetadataEntity.getEndEntityName(),
                                                       credentialMetadataEntity.getMultisign()
                                               )).map(Result::<SessionCredentialMetadata, TextError>success).orElseGet(
                            () -> Result.error(TextError.of("Credential '%s' belonging to session '%s' not found.",
                                                            session.credentialId(), session.id()
                            )));
        } catch (Exception e) {
            logger.error("Failed to get Credential '{}' belonging to session '{}'.", session.credentialId(),
                         session.id(), e
            );
            return Result.error(new TextError("Failed to get session credential."));
        }
    }

    public Result<SessionCredentialMetadata, TextError> createCredential(
            UUID credentialId, SessionKey key, String signatureQualifier, String userId, SignatureActivationData sad,
            CscAuthenticationToken cscAuthenticationToken
    ) {
        var createCredentialResult = signatureQualifierBasedCredentialFactory.createCredential(
                key, signatureQualifier, userId, sad, cscAuthenticationToken
        );
        if (createCredentialResult instanceof Error(var err)) {
            return Result.error(err);
        }
        var signatureQualifierBasedCredentialMetadata = createCredentialResult.unwrap();


        return saveCredentialToDatabase(credentialId, signatureQualifierBasedCredentialMetadata)
                .map(credentialMetadata -> new SessionCredentialMetadata(
                        credentialId, credentialMetadata.key().keyAlias(), credentialMetadata.key().id(),
                        credentialMetadata.endEntityName(), credentialMetadata.multisign()
                )).consume(
                        credentialMetadata -> logger.debug("Created session credential '{}' with key alias '{}'.",
                                                           credentialMetadata.id(), credentialMetadata.keyAlias()
                        )
                )
                .ifError(() -> signatureQualifierBasedCredentialFactory.rollbackCredentialCreation(
                        signatureQualifierBasedCredentialMetadata));
    }

    public Result<Void, TextError> deleteCredential(UUID credentialId) {
        try {
            sessionCredentialsRepository.deleteById(credentialId);
            logger.debug("Deleted session credential '{}'.", credentialId);
            return Result.emptySuccess();
        } catch (Exception e) {
            logger.error("Failed to delete session credential '{}'.", credentialId, e);
            return Result.error(new TextError("Failed to delete session credential."));
        }
    }

    private Result<SignatureQualifierBasedCredentialMetadata<SessionKey>, TextError> saveCredentialToDatabase(
            UUID credentialId, SignatureQualifierBasedCredentialMetadata<SessionKey> credentialMetadata
    ) {
        try {
            logger.trace("Saving session credential '{}' with ID '{}' to the database.", credentialMetadata,
                         credentialId
            );
            SessionCredentialMetadataEntity credentialMetadataEntity = new SessionCredentialMetadataEntity(
                    credentialId, credentialMetadata.userId(), credentialMetadata.key().keyAlias(),
                    credentialMetadata.key().id(),
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
