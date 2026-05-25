package com.otilm.csc.api.mappers.credentials;

import com.otilm.csc.api.auth.SignatureActivationData;
import com.otilm.csc.api.management.SelectCredentialDto;
import com.otilm.csc.common.exceptions.InvalidInputDataException;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CredentialUUIDMapper { //implements RequestMapper<SelectCredentialDto, UUID> {

    //    @Override
    public UUID map(SelectCredentialDto dto, SignatureActivationData sad) throws InvalidInputDataException {

        if (dto.credentialID() == null) {
            throw new InvalidInputDataException("Missing string parameter credentialID.");
        }

        try {
            return UUID.fromString(dto.credentialID());
        } catch (IllegalArgumentException e) {
            throw new InvalidInputDataException("Invalid parameter credentialID.");
        }

    }
}
