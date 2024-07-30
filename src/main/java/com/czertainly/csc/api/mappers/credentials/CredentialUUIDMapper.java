package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.management.SelectCredentialDto;
import com.czertainly.csc.api.mappers.ApiRequestResult;
import com.czertainly.csc.api.mappers.RequestMapper;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CredentialUUIDMapper implements RequestMapper<SelectCredentialDto, UUID> {

    @Override
    public Result<UUID, ErrorWithDescription> map(SelectCredentialDto dto, SignatureActivationData sad) {

        if (dto.credentialID() == null) {
            return ApiRequestResult.invalidRequest("Missing (or invalid type) string parameter credentialID.");
        }

        try {
            UUID uuid = UUID.fromString(dto.credentialID());
            return Result.ok(uuid);
        } catch (IllegalArgumentException e) {
            return ApiRequestResult.invalidRequest("Invalid parameter credentialID.");
        }

    }
}
