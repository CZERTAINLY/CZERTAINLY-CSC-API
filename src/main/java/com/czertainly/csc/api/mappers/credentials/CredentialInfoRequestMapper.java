package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.credentials.GetCredentialInfoDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.CertificateReturnType;
import com.czertainly.csc.model.csc.requests.CredentialInfoRequest;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CredentialInfoRequestMapper {

    public CredentialInfoRequest map(GetCredentialInfoDto dto) {

        if (dto.credentialID() == null) {
            throw InvalidInputDataException.of("Missing (or invalid type) string parameter credentialID.");
        }

        UUID credentialID;
        try {
            credentialID = UUID.fromString(dto.credentialID());
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter credentialID.");
        }

        CertificateReturnType certificateReturnType;
        try {
            certificateReturnType = resolveCertificateReturnType(dto.certificates());
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter certificates.");
        }

        // Default values for returnCertificateInfo and returnAuthInfo are false
        boolean returnCertificateInfo = dto.certInfo() == null ? false : dto.certInfo();
        boolean returnAuthInfo = dto.authInfo() == null ? false : dto.authInfo();


        return new CredentialInfoRequest(
                        credentialID,
                        certificateReturnType,
                        returnCertificateInfo,
                        returnAuthInfo
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
