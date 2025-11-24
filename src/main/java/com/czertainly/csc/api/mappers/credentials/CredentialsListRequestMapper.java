package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.credentials.ListCredentialsRequestDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.common.utils.CertificateMapperUtil;
import com.czertainly.csc.model.csc.CertificateReturnType;
import com.czertainly.csc.model.csc.requests.ListCredentialsRequest;
import org.springframework.stereotype.Component;

@Component
public class CredentialsListRequestMapper {

    public ListCredentialsRequest map(ListCredentialsRequestDto dto, CscAuthenticationToken authenticationToken) {

        String userId = getUserId(dto, authenticationToken);

        CertificateReturnType certificateReturnType;
        try {
            certificateReturnType = CertificateMapperUtil.resolveCertificateReturnType(dto.certificates());
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid parameter certificates.");
        }

        // Default values for returnCertificateInfo and returnAuthInfo are false
        boolean returnCertificateInfo = dto.certInfo() == null ? false : dto.certInfo();
        boolean returnAuthInfo = dto.authInfo() == null ? false : dto.authInfo();
        boolean credentialInfo = dto.credentialInfo() == null ? false : dto.credentialInfo();
        boolean onlyValid = dto.onlyValid() == null ? false : dto.onlyValid();


        return new ListCredentialsRequest(
                userId,
                credentialInfo,
                certificateReturnType,
                returnCertificateInfo,
                returnAuthInfo,
                onlyValid
        );
    }

    private String getUserId(ListCredentialsRequestDto dto, CscAuthenticationToken authenticationToken) {
        String usernameFromToken = extractUserIdFromToken(authenticationToken);
        String userId;
        if (dto.userID() == null) {
            if (usernameFromToken == null) {
                throw InvalidInputDataException.of("Missing (or invalid type) string parameter userID.");
            } else {
                userId = usernameFromToken;
            }
        } else {
            userId = dto.userID();
        }
        return userId;
    }

    private String extractUserIdFromToken(CscAuthenticationToken authenticationToken) {
        if (authenticationToken != null) {
            Object usernameClaim = authenticationToken.getToken().getClaims().get("userID");
            if (usernameClaim == null) {
                throw InvalidInputDataException.of("Missing userID claim in the access token.");
            }
            if (!(usernameClaim instanceof String username)) {
                throw InvalidInputDataException.of("Invalid type of userID claim in the access token. The userID must be a string.");
            } else {
                return username;
            }
        }
        return null;
    }
}
