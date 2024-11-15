package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.configuration.TokenConfiguration;

public interface TokenProvider<TC extends TokenConfiguration, C extends SignatureProcessConfiguration, T extends SigningToken> {

    Result<T, TextError> getSigningToken(C configuration, TC tokenConfiguration, WorkerWithCapabilities worker);

    Result<Void, TextError> cleanup(T signingToken);
}
