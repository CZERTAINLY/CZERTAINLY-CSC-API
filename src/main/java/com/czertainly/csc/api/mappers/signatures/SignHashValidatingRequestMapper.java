package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SADParser;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.signhash.SignHashRequestDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.crypto.AlgorithmPair;
import com.czertainly.csc.crypto.AlgorithmUnifier;
import com.czertainly.csc.model.SignHashParameters;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
public class SignHashValidatingRequestMapper {

    AlgorithmUnifier algorithmUnifier;
    SADParser sadParser;

    public SignHashValidatingRequestMapper(AlgorithmUnifier algorithmUnifier, SADParser sadParser) {
        this.algorithmUnifier = algorithmUnifier;
        this.sadParser = sadParser;
    }

    public SignHashParameters map(SignHashRequestDto dto, SignatureActivationData sad) {
        final List<String> hashes;
        final String keyAlgo;
        final String digestAlgo;
        final OperationMode operationMode;
        final String clientData;

        if (dto == null) throw InvalidInputDataException.of("Missing request parameters.");

        if (dto.getCredentialID().isEmpty()) {
            throw InvalidInputDataException.of("Empty credentialID.");
        }

        final String credentialId = dto.getCredentialID().orElse(null);

        final UUID credentialIdUUID;
        try {
            if (credentialId != null) {
                credentialIdUUID = UUID.fromString(credentialId);
            } else {
                credentialIdUUID = null;
            }
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid string parameter credentialID");
        }

        if (dto.getSAD().isEmpty() && sad == null) {
            throw InvalidInputDataException.of("Missing (or invalid type) string parameter SAD");
        } else if (dto.getSAD().isPresent() && sad != null) {
            throw InvalidInputDataException.of("Signature activation data was provided in both the request" +
                                                       " and the access token. Please provide it in only one place.");
        } else if (dto.getSAD().isPresent()) {
            String sadString = dto.getSAD().get();
            sad = sadParser.parse(sadString);
        }
        final String userID = sad.getUserID()
                                 .orElseThrow(() -> InvalidInputDataException.of(
                                         "Missing userID in Signature Activation Data"));

        if (dto.getHashes().isEmpty()) {
            throw InvalidInputDataException.of("Missing (or invalid type) string parameter credentialID.");
        } else {
            hashes = dto.getHashes().get();
        }

        String signAlgo = dto.getSignAlgo();
        String hashAlgorithmOID = dto.getHashAlgorithmOID();
        AlgorithmPair algorithmPair = algorithmUnifier.unify(signAlgo, hashAlgorithmOID)
                                                      .consumeError(error -> {
                                                          throw InvalidInputDataException.of(error.getErrorText());
                                                      })
                                                      .unwrap();

        keyAlgo = algorithmPair.keyAlgo();
        digestAlgo = algorithmPair.digestAlgo();

        String operationModeString = dto.getOperationMode().orElse("S");
        if (operationModeString.equals("S")) {
            operationMode = OperationMode.SYNCHRONOUS;
        } else if (operationModeString.equals("A")) {
            operationMode = OperationMode.ASYNCHRONOUS;
        } else {
            throw InvalidInputDataException.of("Invalid parameter operationMode.");
        }

        clientData = dto.getClientData().orElse("");

        return new SignHashParameters(credentialIdUUID, userID, hashes, keyAlgo, digestAlgo, sad, operationMode,
                                      clientData
        );
    }
}
