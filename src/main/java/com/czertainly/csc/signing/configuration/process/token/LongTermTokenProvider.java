package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.CredentialMetadata;
import com.czertainly.csc.service.credentials.CredentialsService;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.LongTermTokenConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;

public class LongTermTokenProvider<C extends SignatureProcessConfiguration> implements TokenProvider<LongTermTokenConfiguration, C, LongTermToken> {

    private final CredentialsService credentialsService;

    public LongTermTokenProvider(CredentialsService credentialsService) {
        this.credentialsService = credentialsService;
    }

    @Override
    public Result<LongTermToken, TextError> getSigningToken(
            SignatureProcessConfiguration configuration,
            LongTermTokenConfiguration tokenConfiguration,
            WorkerWithCapabilities worker
    ) {
        var getCredentialresult = credentialsService.getCredentialMetadata(tokenConfiguration.credentialId(),
                                                                           configuration.userID()
        ).mapError(err -> err.extend("Failed to load credential '%s'", tokenConfiguration.credentialId()));
        if (getCredentialresult instanceof Error(var err)) return Result.error(err);
        CredentialMetadata credential = getCredentialresult.unwrap();

        if (credential.signatureQualifier().isPresent() && configuration.signatureQualifier() != null) {
            String signatureQualifier = credential.signatureQualifier().orElseThrow();
            if (!signatureQualifier.equals(configuration.signatureQualifier())) {
                return Result.error(TextError.of(
                        "The signature qualifier '%s' of the requested credential '%s' does not match requested signature qualifier '%s' from the request.",
                        signatureQualifier, credential.id(),
                        configuration.signatureQualifier()
                ));
            }
        }

        return Result.success(new LongTermToken(credential));
    }

    @Override
    public Result<Void, TextError> cleanup(LongTermToken signingToken) {
        return Result.emptySuccess();
    }

}
