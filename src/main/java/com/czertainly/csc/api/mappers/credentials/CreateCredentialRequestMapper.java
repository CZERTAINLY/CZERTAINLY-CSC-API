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

        if (dto.numberOfSignaturesPerAuthorization() == null) {
            return ApiRequestResult.invalidRequest("Missing int parameter numberOfSignaturesPerAuthorization.");
        }

        if (dto.dn() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter dn.");
        }

        if (dto.san() == null) {
            return ApiRequestResult.invalidRequest("Missing string parameter san.");
        }

        return Result.ok(
                new CreateCredentialRequest(
                        dto.cryptoTokenName(),
                        dto.keyAlgorithm(),
                        dto.csrSignatureAlgorithm(),
                        dto.keySpecification(),
                        dto.userId(),
                        dto.signatureQualifier(),
                        dto.numberOfSignaturesPerAuthorization(),
                        dto.scal(),
                        dto.dn(),
                        dto.san(),
                        dto.description()
                )
        );
    }
}
