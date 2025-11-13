package com.czertainly.csc.model.csc.requests;

import com.czertainly.csc.model.csc.CertificateReturnType;

public record ListCredentialsRequest(
        String userID,
        Boolean credentialInfo,
        CertificateReturnType certificateReturnType,
        Boolean certInfo,
        Boolean authInfo,
        Boolean onlyValid
) {
}
