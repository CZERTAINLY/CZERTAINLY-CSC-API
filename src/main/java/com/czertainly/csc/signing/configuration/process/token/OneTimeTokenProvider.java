package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.service.credentials.SignatureQualifierBasedCredentialFactory;
import com.czertainly.csc.signing.KeySelector;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.OneTimeTokenConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

public class OneTimeTokenProvider<C extends SignatureProcessConfiguration> implements TokenProvider<OneTimeTokenConfiguration, C, OneTimeToken> {

    public static final Logger logger = LoggerFactory.getLogger(OneTimeTokenProvider.class);

    private final SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory;
    private final SignserverClient signserverClient;
    private final KeySelector keySelector;

    public OneTimeTokenProvider(
            SignatureQualifierBasedCredentialFactory signatureQualifierBasedCredentialFactory,
            SignserverClient signserverClient, KeySelector keySelector
    ) {
        this.signatureQualifierBasedCredentialFactory = signatureQualifierBasedCredentialFactory;
        this.signserverClient = signserverClient;
        this.keySelector = keySelector;
    }


    @Override
    public Result<OneTimeToken, TextError> getSigningToken(
            SignatureProcessConfiguration signatureConfiguration,
            OneTimeTokenConfiguration tokenConfiguration,
            WorkerWithCapabilities worker
    ) {
        return keySelector.selectKey(worker.worker().workerId())
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
        return signserverClient.removeKey(signingToken.key().cryptoToken().id(), signingToken.getKeyAlias())
                               .consumeError(err -> logger.error("Failed to remove key {} from SignServer: {}",
                                                                 signingToken.getKeyAlias(), err.getErrorText()
                               ))
                               .run(() -> keySelector.markKeyAsUsed(signingToken.key()));
    }
}
