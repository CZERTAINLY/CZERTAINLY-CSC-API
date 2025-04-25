package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.service.credentials.SignatureQualifierBasedCredentialFactory;
import com.czertainly.csc.service.keys.OneTimeKey;
import com.czertainly.csc.service.keys.OneTimeKeyAsyncDeletionService;
import com.czertainly.csc.service.keys.OneTimeKeysService;
import com.czertainly.csc.signing.KeySelector;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.OneTimeTokenConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OneTimeTokenProvider<C extends SignatureProcessConfiguration> implements TokenProvider<OneTimeTokenConfiguration, C, OneTimeToken> {

    public static final Logger logger = LoggerFactory.getLogger(OneTimeTokenProvider.class);

    private final SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory;
    private final KeySelector<OneTimeKey> keySelector;
    private final OneTimeKeysService oneTimeKeysService;
    private final OneTimeKeyAsyncDeletionService asyncDeletionService;

    public OneTimeTokenProvider(
            SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory,
            KeySelector<OneTimeKey> keySelector,
            OneTimeKeysService oneTimeKeysService,
            OneTimeKeyAsyncDeletionService asyncDeletionService
    ) {
        this.signatureQualifierBasedCredentialFactory = signatureQualifierBasedCredentialFactory;
        this.keySelector = keySelector;
        this.oneTimeKeysService = oneTimeKeysService;
        this.asyncDeletionService = asyncDeletionService;
    }


    @Override
    public Result<OneTimeToken, TextError> getSigningToken(
            SignatureProcessConfiguration signatureConfiguration,
            OneTimeTokenConfiguration tokenConfiguration,
            WorkerWithCapabilities worker
    ) {
        return keySelector.selectKey(
                                  worker.worker().workerId(),
                                  signatureConfiguration.signatureAlgorithm().keyAlgorithm()
                          )
                          .flatMap(key -> signatureQualifierBasedCredentialFactory.createCredential(
                                  key,
                                  signatureConfiguration.signatureQualifier(),
                                  signatureConfiguration.userID(),
                                  signatureConfiguration.sad(),
                                  tokenConfiguration.cscAuthenticationToken()
                          ))
                          .map(credential -> new OneTimeToken(
                                  credential.key(), credential.multisign()
                          ))
                          .mapError(e -> e.extend("Failed to create One Time Token"));
    }

    @Override
    public Result<Void, TextError> cleanup(OneTimeToken signingToken) {
        logger.info("Signature complete. Scheduling async deletion for one-time key '{}'", signingToken.key().keyAlias());
        asyncDeletionService.deleteKeyAsync(signingToken.key());
        return Result.emptySuccess();
    }
}
