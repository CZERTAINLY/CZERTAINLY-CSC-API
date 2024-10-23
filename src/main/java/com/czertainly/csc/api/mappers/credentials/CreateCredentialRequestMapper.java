package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.management.CreateCredentialDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.requests.CreateCredentialRequest;
import org.springframework.stereotype.Component;

@Component
public class CreateCredentialRequestMapper {

    public CreateCredentialRequest map(CreateCredentialDto dto
    ) {

        if (dto == null) {
            throw InvalidInputDataException.of("Missing request body.");
        }

        if (dto.cryptoTokenName() == null) {
            throw InvalidInputDataException.of("Missing string parameter cryptoTokenName.");
        }

        if (dto.credentialProfileName() == null) {
            throw InvalidInputDataException.of("Missing string parameter credentialProfileName.");
        }

        if (dto.userId() == null) {
            throw InvalidInputDataException.of("Missing string parameter userId.");
        }

        if (dto.dn() == null) {
            throw InvalidInputDataException.of("Missing string parameter dn.");
        }

        if (dto.san() == null) {
            throw InvalidInputDataException.of("Missing string parameter san.");
        }

        // Check if numberOfSignaturesPerAuthorization is null, and if so, set it to 1.
        // Also, if it is lower than 1, we set it to 1.
        Integer numberOfSignaturesPerAuthorization = dto.numberOfSignaturesPerAuthorization();
        if (numberOfSignaturesPerAuthorization == null || numberOfSignaturesPerAuthorization < 1) {
            numberOfSignaturesPerAuthorization = 1;
        }

        // The description field, if present, must be at most 255 characters long.
        if (dto.description() != null && dto.description().length() > 255) {
            throw InvalidInputDataException.of("The description field must be at most 255 characters long.");
        }

        return new CreateCredentialRequest(
                        dto.cryptoTokenName(),
                        dto.credentialProfileName(),
                        dto.userId(),
                        dto.signatureQualifier(),
                        numberOfSignaturesPerAuthorization,
                        dto.scal(),
                        dto.dn(),
                        dto.san(),
                        dto.description()
        );
    }
}
