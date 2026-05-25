package com.otilm.csc.api.mappers.credentials;

import com.otilm.csc.api.management.RekeyCredentialDto;
import com.otilm.csc.common.exceptions.InvalidInputDataException;
import com.otilm.csc.model.csc.requests.RekeyCredentialRequest;
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
                    dto.credentialProfileName(),
                    dto.cryptoTokenName()
            );
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter credentialID.");
        }
    }
}
