package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.service.credentials.CredentialSession;
import com.czertainly.csc.service.credentials.CredentialSessionsService;
import com.czertainly.csc.service.credentials.SessionCredentialsService;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.SessionTokenConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.UUID;

@Component
public class SessionTokenProvider<C extends SignatureProcessConfiguration> implements TokenProvider<SessionTokenConfiguration, C, SessionToken> {

    private static final Logger logger = LoggerFactory.getLogger(SessionTokenProvider.class);

    private final SignserverClient signserverClient;
    private final CredentialSessionsService credentialSessionsService;
    private final SessionCredentialsService sessionCredentialsService;
    private final CredentialProfileRepository credentialProfileRepository;

    public SessionTokenProvider(SignserverClient signserverClient,
                                CredentialSessionsService credentialSessionsService,
                                SessionCredentialsService sessionCredentialsService,
                                CredentialProfileRepository credentialProfileRepository
    ) {
        this.signserverClient = signserverClient;
        this.credentialSessionsService = credentialSessionsService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.credentialProfileRepository = credentialProfileRepository;
    }

    @Override
    public Result<SessionToken, TextError> getSigningToken(
            SignatureProcessConfiguration configuration,
            SessionTokenConfiguration tokenConfiguration,
            WorkerWithCapabilities worker
    ) {
        var getSessionResult = getExistingOrNewSession(tokenConfiguration.sessionId(), configuration.signatureQualifier());
        if (getSessionResult instanceof Error(var err)) return Result.error(err);
        CredentialSession session = getSessionResult.unwrap();

        var generateCryptoTokenKeyResult = generateCryptoTokenKey(configuration, worker);
        if (generateCryptoTokenKeyResult instanceof Error(var err)) return Result.error(err);
        CryptoTokenKey cryptoTokenKey = generateCryptoTokenKeyResult.unwrap();

        var createCredentialResult = sessionCredentialsService.createCredential(
                                                session, cryptoTokenKey, configuration.signatureQualifier(),
                                                configuration.userID(), configuration.sad(), tokenConfiguration.cscAuthenticationToken()
                                        );
        if (createCredentialResult instanceof Error(var err)) return Result.error(err);
        SessionCredentialMetadata credentialMetadata = createCredentialResult.unwrap();

        return credentialSessionsService.createSession(session)
                .map(success -> new SessionToken(credentialMetadata));

    }

    @Override
    public Result<Void, TextError> cleanup(SessionToken signingToken) {
        return Result.emptySuccess();
    }

    private Result<CredentialSession, TextError> getExistingOrNewSession(UUID sessionId, String signatureQualifier) {
        return credentialSessionsService.getSessionStatus(sessionId)
                                        .flatMap(status -> switch (status) {
                                            case ACTIVE -> credentialSessionsService.getSession(sessionId);
                                            case EXPIRED ->
                                                    Result.error(TextError.of("Session '%s' is expired", sessionId));
                                            case NONEXISTENT -> createSession(sessionId, signatureQualifier);
                                        })
                                        .mapError(err -> TextError.of("Creation of a session '%s' has failed",
                                                                      sessionId
                                        ));
    }

    private Result<CredentialSession, TextError> createSession(UUID sessionId, String signatureQualifier) {
        UUID credentialId = UUID.randomUUID();
        return computeExpiresAt(signatureQualifier)
                .map(expiresAt -> new CredentialSession(sessionId, credentialId, expiresAt));
    }

    private Result<ZonedDateTime, TextError> computeExpiresAt(String signatureQualifier) {
        return credentialProfileRepository.getSignatureQualifierProfile(signatureQualifier)
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

    private Result<CryptoTokenKey, TextError> generateCryptoTokenKey(
            SignatureProcessConfiguration configuration, WorkerWithCapabilities worker
    ) {
        String uniqueUserId = createUniqueUserId(configuration.userID());
        String partialKeyAlias = getUniqueKeyAlias(uniqueUserId);
        CryptoToken token = worker.worker().cryptoToken();
        String keyAlgorithm = configuration.signatureAlgorithm().keyAlgorithm();
        String keySpecification = "2048"; // TODO: load keyspec from profile?

        return signserverClient.generateKey(token, partialKeyAlias, keyAlgorithm, keySpecification)
                               .mapError(err -> TextError.of("Failed to generate key for user %s",
                                                             uniqueUserId
                               ))
                               .map(keyAlias -> new CryptoTokenKey(token, keyAlias, keyAlgorithm,
                                                                   keySpecification, null, null
                               ));
    }

    private String createUniqueUserId(String userID) {
        String random_id = RandomStringUtils.secureStrong().next(8, true, true);
        String uniqueUserId = String.format("%s-%s", userID, random_id);
        logger.trace("Generated new unique user id {}", uniqueUserId);
        return uniqueUserId;
    }

    private String getUniqueKeyAlias(String userId) {
        String random_id = RandomStringUtils.secureStrong().next(8, true, true);
        String alias = String.format("%s-%s", userId, random_id);
        logger.trace("Generated new unique key alias {}", alias);
        return alias;
    }

}
