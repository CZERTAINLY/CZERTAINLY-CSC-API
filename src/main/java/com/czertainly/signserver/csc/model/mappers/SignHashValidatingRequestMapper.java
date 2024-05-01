package com.czertainly.signserver.csc.model.mappers;

import com.czertainly.signserver.csc.api.OperationMode;
import com.czertainly.signserver.csc.api.auth.SADParser;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;
import com.czertainly.signserver.csc.crypto.AlgorithmPair;
import com.czertainly.signserver.csc.crypto.AlgorithmUnifier;
import com.czertainly.signserver.csc.api.signhash.SignHashRequestDto;
import com.czertainly.signserver.csc.model.SignHashParameters;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SignHashValidatingRequestMapper implements SignatureRequestMapper<SignHashRequestDto, SignHashParameters> {

    AlgorithmUnifier algorithmUnifier;
    SADParser sadParser;

    public static final String INVALID_REQUEST = "invalid_request";

    public SignHashValidatingRequestMapper(AlgorithmUnifier algorithmUnifier, SADParser sadParser) {
        this.algorithmUnifier = algorithmUnifier;
        this.sadParser = sadParser;
    }

    @Override
    public Result<SignHashParameters, ErrorWithDescription> map(SignHashRequestDto dto, SignatureActivationData sad) {
        final List<String> hashes;
        final String keyAlgo;
        final String digestAlgo;
        final OperationMode operationMode;
        final String clientData;

        if (dto == null) return toInvalidRequestError("Missing request parameters.");

        if (dto.getSAD().isEmpty() && sad == null) {
            return toInvalidRequestError("Missing (or invalid type) string parameter SAD");
        } else if (dto.getSAD().isPresent() && sad != null) {
            return toInvalidRequestError("Signature activation data was provided in both the request" +
                                             " and the access token. Please provide it in only one place.");
        } else if (dto.getSAD().isPresent()) {
            String sadString = dto.getSAD().get();
            sad = sadParser.parse(sadString);
        }

        if (dto.getHashes().isEmpty()) {
            return toInvalidRequestError("Missing (or invalid type) string parameter credentialID.");
        } else {
            hashes = dto.getHashes().get();
        }

        String signAlgo = dto.getSignAlgo();
        String hashAlgorithmOID = dto.getHashAlgorithmOID();
        Result<AlgorithmPair, ErrorWithDescription> result = algorithmUnifier.unify(signAlgo, hashAlgorithmOID);
        if (result.isError()) {
            return Result.error(result.getError());
        } else {
            AlgorithmPair algorithmPair = result.getValue();
            keyAlgo = algorithmPair.keyAlgo();
            digestAlgo = algorithmPair.digestAlgo();
        }

        String operationModeString = dto.getOperationMode().orElse("S");
        if (operationModeString.equals("S")) {
            operationMode = OperationMode.SYNCHRONOUS;
        } else if (operationModeString.equals("A")) {
            operationMode = OperationMode.ASYNCHRONOUS;
        } else {
            return toInvalidRequestError("Invalid parameter operationMode.");
        }

        clientData = dto.getClientData().orElse("");


        return Result.ok(
                new SignHashParameters(hashes, keyAlgo, digestAlgo, sad, operationMode, clientData)
        );
    }

    private Result<SignHashParameters, ErrorWithDescription> toInvalidRequestError(String errorMessage) {
        return Result.error(new ErrorWithDescription(INVALID_REQUEST, errorMessage));
    }

}
