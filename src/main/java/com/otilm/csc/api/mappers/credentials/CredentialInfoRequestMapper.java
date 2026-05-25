package com.otilm.csc.api.mappers.credentials;

import com.otilm.csc.api.auth.CscAuthenticationToken;
import com.otilm.csc.api.credentials.GetCredentialInfoDto;
import com.otilm.csc.common.exceptions.InvalidInputDataException;
import com.otilm.csc.common.utils.CertificateMapperUtil;
import com.otilm.csc.model.csc.CertificateReturnType;
import com.otilm.csc.model.csc.requests.CredentialInfoRequest;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CredentialInfoRequestMapper {

    public CredentialInfoRequest map(GetCredentialInfoDto dto, CscAuthenticationToken authenticationToken) {

        String userId = extractUserIdFromToken(authenticationToken);

        UUID credentialID;
        try {
            credentialID = UUID.fromString(dto.credentialID());
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter credentialID.");
        }

        CertificateReturnType certificateReturnType;
        try {
            certificateReturnType = CertificateMapperUtil.resolveCertificateReturnType(dto.certificates());
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter certificates.");
        }

        // Default values for returnCertificateInfo and returnAuthInfo are false
        boolean returnCertificateInfo = dto.certInfo() == null ? false : dto.certInfo();
        boolean returnAuthInfo = dto.authInfo() == null ? false : dto.authInfo();


        return new CredentialInfoRequest(
                userId,
                credentialID,
                certificateReturnType,
                returnCertificateInfo,
                returnAuthInfo
        );
    }

    private String extractUserIdFromToken(CscAuthenticationToken authenticationToken) {
        if (authenticationToken != null) {
            Object usernameClaim = authenticationToken.getToken().getClaims().get("userID");
            if (usernameClaim == null) {
                throw InvalidInputDataException.of("Missing userID claim in the access token.");
            }
            if (!(usernameClaim instanceof String username)) {
                throw InvalidInputDataException.of(
                        "Invalid type of userID claim in the access token. The userID must be a string.");
            } else {
                return username;
            }
        }
        return null;
    }
}
