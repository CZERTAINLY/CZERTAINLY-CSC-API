package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.credentials.CredentialInfoDto;
import com.czertainly.csc.api.mappers.ApiRequestResult;
import com.czertainly.csc.api.mappers.RequestMapper;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.csc.CertificateReturnType;
import com.czertainly.csc.model.csc.requests.CredentialInfoRequest;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CredentialInfoRequestMapper implements RequestMapper<CredentialInfoDto, CredentialInfoRequest> {

    @Override
    public Result<CredentialInfoRequest, ErrorWithDescription> map(CredentialInfoDto dto, SignatureActivationData sad) {

        if (dto.credentialID() == null) {
            return ApiRequestResult.invalidRequest("Missing (or invalid type) string parameter credentialID.");
        }

        UUID credentialID;
        try {
            credentialID = UUID.fromString(dto.credentialID());
        } catch (IllegalArgumentException e) {
            return ApiRequestResult.invalidRequest("Invalid parameter credentialID.");
        }

        CertificateReturnType certificateReturnType;
        try {
            certificateReturnType = resolveCertificateReturnType(dto.certificates());
        } catch (IllegalArgumentException e) {
            return ApiRequestResult.invalidRequest("Invalid parameter certificates.");
        }

        // Default values for returnCertificateInfo and returnAuthInfo are false
        boolean returnCertificateInfo = dto.certInfo() == null ? false : dto.certInfo();
        boolean returnAuthInfo = dto.authInfo() == null ? false : dto.authInfo();


        return Result.ok(
                new CredentialInfoRequest(
                        credentialID,
                        certificateReturnType,
                        returnCertificateInfo,
                        returnAuthInfo
                )
        );
    }

    private CertificateReturnType resolveCertificateReturnType(String certificateReturnType
    ) throws IllegalArgumentException {
        if (certificateReturnType == null) {
            return CertificateReturnType.END_CERTIFICATE;
        }
        return CertificateReturnType.valueOf(certificateReturnType);
    }
}
