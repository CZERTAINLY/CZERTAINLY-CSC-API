package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.SignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;

import java.util.List;

public interface DocumentSigner<C extends SignatureProcessConfiguration> {

    Result<SignedDocuments, TextError> sign(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    );

}
