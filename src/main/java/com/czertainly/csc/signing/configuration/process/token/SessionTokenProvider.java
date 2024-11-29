package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.service.credentials.CredentialSessionStatus;
import com.czertainly.csc.service.credentials.SessionCredentialsService;
import com.czertainly.csc.service.credentials.SigningSession;
import com.czertainly.csc.service.credentials.SigningSessionsService;
import com.czertainly.csc.service.keys.KeysService;
import com.czertainly.csc.service.keys.SessionKey;
import com.czertainly.csc.service.keys.SessionKeysService;
import com.czertainly.csc.signing.KeySelector;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.SessionTokenConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;

@Component
public class SessionTokenProvider<C extends SignatureProcessConfiguration> implements TokenProvider<SessionTokenConfiguration, C, SessionToken> {

    private static final Logger logger = LoggerFactory.getLogger(SessionTokenProvider.class);

    private final SigningSessionsService signingSessionsService;
    private final SessionCredentialsService sessionCredentialsService;
    private final CredentialProfileRepository credentialProfileRepository;
    private final KeySelector<SessionKey> sessionKeySelector;
    private final KeysService<SessionKey> keysService;

    public SessionTokenProvider(SigningSessionsService signingSessionsService,
                                SessionCredentialsService sessionCredentialsService,
                                CredentialProfileRepository credentialProfileRepository,
                                KeySelector<SessionKey> sessionKeySelector, SessionKeysService keysService
    ) {
        this.signingSessionsService = signingSessionsService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.credentialProfileRepository = credentialProfileRepository;
        this.sessionKeySelector = sessionKeySelector;
        this.keysService = keysService;
    }

    @Override
    public Result<SessionToken, TextError> getSigningToken(
            SignatureProcessConfiguration configuration,
            SessionTokenConfiguration tokenConfiguration,
            WorkerWithCapabilities worker
    ) {
        logger.debug("Obtaining signing token for session '{}'.", tokenConfiguration.sessionId());
        var getSessionResult = signingSessionsService.getSession(tokenConfiguration.sessionId());
        if (getSessionResult instanceof Error(var err)) return Result.error(err);
        Optional<SigningSession> existingSession = getSessionResult.unwrap();

        if (existingSession.isEmpty()) {
            var createSessionResult = createSession(tokenConfiguration.sessionId(), configuration.signatureQualifier());
            if (createSessionResult instanceof Error(var err)) return Result.error(err);
            SigningSession newSession = createSessionResult.unwrap();

            var selectKeyResult = sessionKeySelector.selectKey(
                    worker.worker().workerId(),
                    configuration.signatureAlgorithm().keyAlgorithm()
            );
            if (selectKeyResult instanceof Error(var err)) return Result.error(err);
            SessionKey sessionKey = selectKeyResult.unwrap();

            var createCredentialResult = sessionCredentialsService
                    .createCredential(
                            newSession.credentialId(), sessionKey,
                            configuration.signatureQualifier(),
                            configuration.userID(), configuration.sad(),
                            tokenConfiguration.cscAuthenticationToken()
                    )
                    .ifError(() -> removeSessionKey(sessionKey));
            if (createCredentialResult instanceof Error(var err)) return Result.error(err);
            SessionCredentialMetadata credentialMetadata = createCredentialResult.unwrap();

            return signingSessionsService.saveNewSession(newSession)
                                         .map(s -> new SessionToken(credentialMetadata, s))
                                         .consume(s -> logger.debug(
                                                 "New session '{}' has been created. Associated credential '{}' and key '{}' .",
                                                 newSession.id(), credentialMetadata.id(), credentialMetadata.keyAlias()
                                         ))
                                         .consumeError(err -> {
                                             rollbackSessionCredentialCreation(newSession.credentialId());
                                             removeSessionKey(sessionKey);
                                         });
        } else {
            return sessionCredentialsService.getSessionCredential(existingSession.get())
                                            .consume(credential -> logger.debug(
                                                    "Session '{}' already exists. Will reuse credential '{}' with key '{}'",
                                                    existingSession.get().id(), credential.id(), credential.keyAlias()
                                            ))
                                            .map(credential -> new SessionToken(credential, existingSession.get()));
        }
    }

    @Override
    public Result<Void, TextError> cleanup(SessionToken signingToken) {
        return Result.emptySuccess();
    }

    private Result<SigningSession, TextError> createSession(UUID sessionId, String signatureQualifier) {
        UUID credentialId = UUID.randomUUID();
        logger.trace("Creating a new session '{}'.", sessionId);
        return computeExpiresAt(signatureQualifier)
                .map(expiresAt -> new SigningSession(sessionId, credentialId, expiresAt,
                                                     CredentialSessionStatus.NEW
                ))
                .consume(session -> logger.trace("A new signing session created '{}'.", session));
    }

    private Result<ZonedDateTime, TextError> computeExpiresAt(String signatureQualifier) {
        return credentialProfileRepository.getSignatureQualifierProfile(signatureQualifier)
                                          .consume(profile -> logger.debug(
                                                  "Computing the session expiration time using the signature qualifier profile '{}'.",
                                                  profile
                                          ))
                                          .flatMap(profile -> {
                                              try {
                                                  ZonedDateTime now = ZonedDateTime.now();
                                                  var expiresAt = now.plus(profile.getCertificateValidityOffset())
                                                                     .plus(profile.getCertificateValidity());
                                                  return Result.success(expiresAt);
                                              } catch (Exception e) {
                                                  logger.error("Failed to compute session expiration time.", e);
                                                  return Result.error(
                                                          TextError.of("Failed to compute session expiration time."));
                                              }
                                          });
    }

    private void rollbackSessionCredentialCreation(UUID credentialId) {
        logger.info("Rolling back creation of a session credential '{}'.", credentialId);
        sessionCredentialsService.deleteCredential(credentialId)
                                 .consumeError(
                                         err -> logger.warn("Failed to rollback creation of a session credential '{}'.",
                                                            err.getErrorText()
                                         ));
        logger.trace("Successfully rolled back the creation of a session credential '{}'.", credentialId);
    }

    private void removeSessionKey(SessionKey key) {
        logger.debug("Removing session key '{}'", key);
        keysService.deleteKey(key)
                   .consumeError(err -> logger.error("Failed to remove session key '{}'. {}", key,
                                                     err.getErrorText()
                   ));
        logger.trace("Successfully removed session key '{}'", key);
    }
}
