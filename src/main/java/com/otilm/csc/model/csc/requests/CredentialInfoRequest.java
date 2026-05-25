package com.otilm.csc.model.csc.requests;

import com.otilm.csc.model.csc.CertificateReturnType;

import java.util.UUID;

public record CredentialInfoRequest(
        String userID,
        UUID credentialID,
        CertificateReturnType certificateReturnType,
        Boolean returnCertificateInfo,
        Boolean returnAuthInfo
) {

}
