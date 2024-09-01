package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.management.RekeyCredentialDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.requests.RekeyCredentialRequest;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class RekeyCertificateRequestMapper {

    public RekeyCredentialRequest map(RekeyCredentialDto dto) throws InvalidInputDataException {

        if (dto.credentialID() == null || dto.credentialID().isBlank()) {
            throw InvalidInputDataException.of("Missing string parameter credentialID.");
        }

        try {
            UUID uuid = UUID.fromString(dto.credentialID());

            return new RekeyCredentialRequest(
                    uuid,
                    dto.cryptoTokenName(),
                    dto.keyAlgorithm(),
                    dto.keySpecification(),
                    dto.csrSignatureAlgorithm()
            );
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter credentialID.");
        }
    }
}
