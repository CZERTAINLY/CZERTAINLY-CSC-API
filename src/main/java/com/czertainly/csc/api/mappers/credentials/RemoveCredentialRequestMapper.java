package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.management.RemoveCredentialDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.requests.RemoveCredentialRequest;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class RemoveCredentialRequestMapper {

    public RemoveCredentialRequest map(RemoveCredentialDto dto) {
        if (dto == null) {
            throw InvalidInputDataException.of("Missing request body.");
        }

        if (dto.credentialID() == null || dto.credentialID().isBlank()) {
            throw InvalidInputDataException.of("Missing string parameter credentialID.");
        }

        try {
            UUID uuid = UUID.fromString(dto.credentialID());

            return new RemoveCredentialRequest(
                    uuid,
                    dto.revocationReason()
            );
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter credentialID.");
        }
    }
}
