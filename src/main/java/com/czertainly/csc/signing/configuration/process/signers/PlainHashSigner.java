package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.PlainSignature;
import com.czertainly.csc.model.SignaturesContainer;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.PlainHashSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class PlainHashSigner<C extends PlainHashSignatureProcessConfiguration> implements Signer<C, PlainSignature> {

    public static final Logger logger = LoggerFactory.getLogger(PlainHashSigner.class);

    private final SignserverClient signserverClient;

    public PlainHashSigner(
            SignserverClient signserverClient
    ) {
        this.signserverClient = signserverClient;
    }

    @Override
    public Result<SignaturesContainer<PlainSignature>, TextError> sign(List<String> data, C configuration,
                                                                       SigningToken signingToken,
                                                                       WorkerWithCapabilities worker
    ) {
        Result<SignaturesContainer<PlainSignature>, TextError> result;
        if (data.size() == 1) {
            result = signSingleHash(data, configuration, signingToken, worker);
        } else {
            result = signMultipleHashes(data, configuration, signingToken, worker);
        }

        return result.flatMap(signed -> verifyNumberOfSignatures(data, signed));
    }

    private Result<SignaturesContainer<PlainSignature>, TextError> verifyNumberOfSignatures(List<String> data,
                                                                                            SignaturesContainer<PlainSignature> signed
    ) {
        if (signed.signatures().size() != data.size()) {
            logger.error("The number of signatures does not match the number of documents.");
            return Result.error(TextError.of("The number of signatures does not match the number of documents."));
        }
        return Result.success(signed);
    }

    private Result<SignaturesContainer<PlainSignature>, TextError> signSingleHash(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signPlainSingleHash(
                worker.worker().workerName(),
                data.getFirst().getBytes(),
                signingToken.getKeyAlias(),
                configuration.encryptionAlgorithm(),
                configuration.digestAlgorithm()
        );
    }

    private Result<SignaturesContainer<PlainSignature>, TextError> signMultipleHashes(
            List<String> data, C configuration, SigningToken signingToken, WorkerWithCapabilities worker
    ) {
        return signserverClient.signPlainMultipleHashes(
                worker.worker().workerName(),
                data,
                signingToken.getKeyAlias(),
                configuration.encryptionAlgorithm(),
                configuration.digestAlgorithm()
        );
    }
}
