package com.otilm.csc.signing.configuration.process.signers;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.model.Signature;
import com.otilm.csc.model.SignaturesContainer;
import com.otilm.csc.signing.configuration.WorkerWithCapabilities;
import com.otilm.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.otilm.csc.signing.configuration.process.token.SigningToken;

import java.util.List;

public interface Signer<C extends SignatureProcessConfiguration, S extends Signature> {

    Result<SignaturesContainer<S>, TextError> sign(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    );

}
