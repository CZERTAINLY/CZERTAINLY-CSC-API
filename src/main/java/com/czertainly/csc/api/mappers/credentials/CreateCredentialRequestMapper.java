package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.management.CreateCredentialDto;
import com.czertainly.csc.api.mappers.ApiRequestResult;
import com.czertainly.csc.api.mappers.RequestMapper;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.csc.requests.CreateCredentialRequest;
import org.springframework.stereotype.Component;

@Component
public class CreateCredentialRequestMapper implements RequestMapper<CreateCredentialDto, CreateCredentialRequest> {


    @Override
    public Result<CreateCredentialRequest, ErrorWithDescription> map(CreateCredentialDto dto,
                                                                     SignatureActivationData sad
    ) {

        if (dto == null) {
            return ApiRequestResult.invalidRequest("Missing request body.");
        }

        if (dto.cryptoTokenName() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter cryptoTokenName.");
        }

        if (dto.keyAlgorithm() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter keyAlgorithm.");
        }

        if (dto.csrSignatureAlgorithm() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter csrSignatureAlgorithm.");
        }

        if (dto.keySpecification() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter keySpecification.");
        }

        if (dto.userId() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter userId.");
        }

        if (dto.dn() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter dn.");
        }

        if (dto.san() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter san.");
        }

        // Check if numberOfSignaturesPerAuthorization is null, and if so, set it to 1.
        // Also, if it is lower than 1, we set it to 1.
        Integer numberOfSignaturesPerAuthorization = dto.numberOfSignaturesPerAuthorization();
        if (numberOfSignaturesPerAuthorization == null || numberOfSignaturesPerAuthorization < 1) {
            numberOfSignaturesPerAuthorization = 1;
        }

        // The description field, if present, must be at most 255 characters long.
        if (dto.description() != null && dto.description().length() > 255) {
            return ApiRequestResult.invalidRequest("The description field must be at most 255 characters long.");
        }

        return Result.ok(
                new CreateCredentialRequest(
                        dto.cryptoTokenName(),
                        dto.keyAlgorithm(),
                        dto.csrSignatureAlgorithm(),
                        dto.keySpecification(),
                        dto.userId(),
                        dto.signatureQualifier(),
                        numberOfSignaturesPerAuthorization,
                        dto.scal(),
                        dto.dn(),
                        dto.san(),
                        dto.description()
                )
        );
    }
}
