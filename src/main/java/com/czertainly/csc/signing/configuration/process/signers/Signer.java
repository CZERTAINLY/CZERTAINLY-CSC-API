package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.Signature;
import com.czertainly.csc.model.SignaturesContainer;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;

import java.util.List;

public interface Signer<C extends SignatureProcessConfiguration, S extends Signature> {

    Result<SignaturesContainer<S>, TextError> sign(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    );

}
