package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.management.RekeyCredentialDto;
import com.czertainly.csc.api.mappers.ApiRequestResult;
import com.czertainly.csc.api.mappers.RequestMapper;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.csc.requests.RekeyCredentialRequest;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class RekeyCertificateRequestMapper implements RequestMapper<RekeyCredentialDto, RekeyCredentialRequest> {

    public Result<RekeyCredentialRequest, ErrorWithDescription> map(RekeyCredentialDto dto,
                                                                    SignatureActivationData sad
    ) {

        if (dto.credentialID() == null || dto.credentialID().isBlank()) {
            return ApiRequestResult.invalidRequest("Missing (or invalid type) string parameter credentialID.");
        }

        try {
            UUID uuid = UUID.fromString(dto.credentialID());

            return Result.ok(new RekeyCredentialRequest(
                    uuid,
                    dto.cryptoTokenName(),
                    dto.keyAlgorithm(),
                    dto.keySpecification(),
                    dto.csrSignatureAlgorithm()
            ));
        } catch (IllegalArgumentException e) {
            return ApiRequestResult.invalidRequest("Invalid parameter credentialID.");
        }
    }

}
