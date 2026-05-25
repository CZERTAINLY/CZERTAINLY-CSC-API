package com.otilm.csc.model.csc.requests;

import com.otilm.csc.model.csc.CertificateReturnType;

public record ListCredentialsRequest(
        String userID,
        Boolean credentialInfo,
        CertificateReturnType certificateReturnType,
        Boolean certInfo,
        Boolean authInfo,
        Boolean onlyValid
) {
}
