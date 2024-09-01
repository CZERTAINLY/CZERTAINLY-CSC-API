package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.credentials.ListCredentialsRequestDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.CertificateReturnType;
import com.czertainly.csc.model.csc.requests.ListCredentialsRequest;
import org.springframework.stereotype.Component;

@Component
public class CredentialsListRequestMapper {

    public ListCredentialsRequest map(ListCredentialsRequestDto dto) {

        if (dto.userID() == null) {
            throw InvalidInputDataException.of("Missing (or invalid type) string parameter userID.");
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
        boolean credentialInfo = dto.credentialInfo() == null ? false : dto.credentialInfo();
        boolean onlyValid = dto.onlyValid() == null ? false : dto.onlyValid();


        return new ListCredentialsRequest(
                dto.userID(),
                credentialInfo,
                certificateReturnType,
                returnCertificateInfo,
                returnAuthInfo,
                onlyValid
        );
    }

    private CertificateReturnType resolveCertificateReturnType(String certificateReturnType
    ) throws IllegalArgumentException {
        if (certificateReturnType == null) {
            return CertificateReturnType.END_CERTIFICATE;
        }
        return switch (certificateReturnType) {
            case "none" -> CertificateReturnType.NONE;
            case "single" -> CertificateReturnType.END_CERTIFICATE;
            case "chain" -> CertificateReturnType.CERTIFICATE_CHAIN;
            default -> throw new IllegalArgumentException("Invalid certificateReturnType value.");
        };
    }
}
